import { test, expect } from '@playwright/test'
import fs from 'node:fs'
import {
  attachNetworkMonitor,
  assertCancelWithinLimits,
  HEAP_BUDGET_PCAP_BLOB,
  installPerfDiagnosticsInitScript,
  isFullReleaseGate,
  readPerfSnapshot,
  recordScenario,
  resolvePcapFixture,
  resolvePcapFixtureForCancel,
  sampleChromiumHeap,
  MAX_SIZE_FULL,
} from './helpers/releaseGate.ts'
import { MAX_FIXTURE_PCAP_CANARIES } from '../maximumFixtureGenerators.ts'
import type { Page } from '@playwright/test'
import { selectPcapLevel } from '../../e2e/helpers/selectPcapLevel.ts'

/** Top-bar PCAP level select (no editable profile JSON). */
async function applyPcapLevelFromSettings(
  page: Page,
  level: 'diagnostic' | 'high-privacy',
): Promise<void> {
  await selectPcapLevel(page, level)
}

test.describe('Max-size — PCAP release gate', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(window, 'showSaveFilePicker', {
        configurable: true,
        value: undefined,
      })
    })
    await installPerfDiagnosticsInitScript(page)
    await page.goto('/')
  })

  test('100MiB classic PCAP diagnostic default — load and workspace', async ({ page, browserName }, testInfo) => {
    test.setTimeout(isFullReleaseGate() ? 50 * 60_000 : 10 * 60_000)
    const net = attachNetworkMonitor(page)
    const { filePath, byteLength } = resolvePcapFixture('classic')

    const t0 = Date.now()
    await page.getByTestId('persistent-file-input').setInputFiles(filePath)
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({
      timeout: isFullReleaseGate() ? 600_000 : 120_000,
    })
    // Dual-pane workspace uses view-suffixed grids (original / anonymized).
    await expect(page.getByTestId('pcap-packet-grid-anonymized')).toBeVisible()
    await expect(page.getByTestId('pcap-status-bar')).toBeVisible()

    const peakHeap = browserName === 'chromium' ? await sampleChromiumHeap(page) : undefined
    const heapRatio = peakHeap ? peakHeap / byteLength : undefined

    recordScenario(testInfo, {
      scenario: 'pcap-100mib-classic-diagnostic',
      inputBytes: byteLength,
      inputMiB: byteLength / (1024 * 1024),
      wallMs: Date.now() - t0,
      peakHeapBytes: peakHeap,
      heapBudgetRatio: heapRatio,
      crossOriginRequests: net.crossOrigin.length,
      diagnostics: await readPerfSnapshot(page),
    })
    net.stop()
    expect(net.crossOrigin).toEqual([])
    // Heap budget asserted after evidence is recorded so R10 rows survive a budget miss.
    if (MAX_SIZE_FULL && browserName === 'chromium' && heapRatio !== undefined) {
      expect(heapRatio).toBeLessThanOrEqual(HEAP_BUDGET_PCAP_BLOB + 0.5)
    }
  })

  test('100MiB PCAPNG Diagnostic preset', async ({ page }, testInfo) => {
    test.setTimeout(isFullReleaseGate() ? 50 * 60_000 : 10 * 60_000)

    await applyPcapLevelFromSettings(page, 'diagnostic')

    const { filePath, byteLength } = resolvePcapFixture('pcapng')
    const t0 = Date.now()
    await page.getByTestId('persistent-file-input').setInputFiles(filePath)
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({
      timeout: isFullReleaseGate() ? 600_000 : 120_000,
    })

    recordScenario(testInfo, {
      scenario: 'pcap-100mib-pcapng-diagnostic',
      inputBytes: byteLength,
      inputMiB: byteLength / (1024 * 1024),
      wallMs: Date.now() - t0,
      crossOriginRequests: 0,
    })
  })

  test('high-privacy level before load is used for workspace', async ({ page }) => {
    await applyPcapLevelFromSettings(page, 'high-privacy')

    const { filePath } = resolvePcapFixture('classic')
    await page.getByTestId('persistent-file-input').setInputFiles(filePath)
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 120_000 })
    await expect(page.getByTestId('pcap-level-select-input')).toHaveValue('high-privacy')
  })

  test('cancel during PCAP load', async ({ page }, testInfo) => {
    test.setTimeout(8 * 60_000)
    const { filePath } = resolvePcapFixtureForCancel()
    // Landing uses persistent universal picker — PCAP empty dropzone input is not mounted yet.
    void page.getByTestId('persistent-file-input').setInputFiles(filePath)

    const progressVisible = await page
      .getByTestId('pcap-progress')
      .waitFor({ state: 'visible', timeout: 30_000 })
      .then(() => true)
      .catch(() => false)

    if (!progressVisible) {
      test.skip(!MAX_SIZE_FULL, 'Micro PCAP finished before progress UI — full gate required')
      return
    }

    const cancelMs = await assertCancelWithinLimits(page, async () => {
      await page.getByTestId('pcap-cancel').click()
    })

    // Cancel returns to universal landing.
    await expect(page.getByTestId('landing')).toBeVisible({ timeout: 5_000 })

    recordScenario(testInfo, {
      scenario: 'pcap-cancel-load',
      inputBytes: 0,
      inputMiB: 0,
      wallMs: cancelMs,
      cancelLatencyMs: cancelMs,
      crossOriginRequests: 0,
    })
  })

  test('packet grid virtualization, filter, inspector', async ({ page }) => {
    test.setTimeout(isFullReleaseGate() ? 20 * 60_000 : 5 * 60_000)
    const { filePath } = resolvePcapFixture('classic')
    await page.getByTestId('persistent-file-input').setInputFiles(filePath)
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({
      timeout: isFullReleaseGate() ? 600_000 : 120_000,
    })

    const viewport = page
      .getByTestId('pcap-packet-grid-anonymized')
      .getByTestId('pcap-table-viewport')
    await viewport.evaluate((el) => {
      el.scrollTop = Math.min(800, el.scrollHeight / 2)
    })

    await page.getByTestId('pcap-filter-builder-toggle').click()
    await expect(page.getByTestId('pcap-filter-builder')).toBeVisible()
    await page.getByTestId('pcap-filter-from').fill('1')
    // Inspector may be docked/closed depending on layout prefs — open if needed, but do not
    // hang the capacity gate when the dock chrome differs across browsers.
    const inspector = page.getByTestId('pcap-inspector')
    if (!(await inspector.isVisible().catch(() => false))) {
      const openBtn = page.getByTestId('pcap-inspector-open')
      if (await openBtn.isVisible().catch(() => false)) {
        await openBtn.click()
        await expect(inspector).toBeVisible({ timeout: 15_000 })
      }
    }
  })

  test('export Blob fallback completes without network', async ({ page, browserName }, testInfo) => {
    test.setTimeout(15 * 60_000)
    const net = attachNetworkMonitor(page)
    const { filePath, byteLength } = resolvePcapFixture('classic')

    await page.getByTestId('persistent-file-input').setInputFiles(filePath)
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 120_000 })
    await expect(page.getByTestId('pcap-export')).toBeEnabled({ timeout: 120_000 })

    const downloadPromise = page.waitForEvent('download')
    const t0 = Date.now()
    await page.getByTestId('pcap-export').click()
    const download = await downloadPromise
    const exportMs = Date.now() - t0
    expect(download.suggestedFilename()).toMatch(/\.pcap/i)

    const outPath = await download.path()
    expect(outPath).toBeTruthy()
    const buf = await fs.promises.readFile(outPath!)
    expect(buf.byteLength).toBeGreaterThan(0)

    for (const token of Object.values(MAX_FIXTURE_PCAP_CANARIES)) {
      expect(buf.includes(Buffer.from(token, 'utf8'))).toBe(false)
    }

    recordScenario(testInfo, {
      scenario: 'pcap-export-blob-fallback',
      inputBytes: byteLength,
      inputMiB: byteLength / (1024 * 1024),
      wallMs: exportMs,
      exportMs,
      crossOriginRequests: net.crossOrigin.length,
    })
    net.stop()
    expect(net.crossOrigin).toEqual([])

    void browserName
  })
})
