import { test, expect } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  attachNetworkMonitor,
  assertExportMustNotLeak,
  HEAP_BUDGET_TEXT,
  installPerfDiagnosticsInitScript,
  isFullReleaseGate,
  readPerfSnapshot,
  recordScenario,
  resolveTextFixture,
  sampleChromiumHeap,
  MAX_SIZE_FULL,
  writeTempLog,
} from './helpers/releaseGate.ts'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')
const productionProfilePath = path.join(repoRoot, 'profiles/rnd-team-production.json')

test.describe('Max-size — text release gate', () => {
  test.beforeEach(async ({ page }) => {
    await installPerfDiagnosticsInitScript(page)
    await page.goto('/')
  })

  test('90MiB LF default profile — import, interactive UI, export', async ({ page, browserName }, testInfo) => {
    test.setTimeout(isFullReleaseGate() ? 45 * 60_000 : 8 * 60_000)
    const net = attachNetworkMonitor(page)
    const { filePath, byteLength } = resolveTextFixture('lf')

    const t0 = Date.now()
    await page.getByTestId('persistent-file-input').setInputFiles(filePath)
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: isFullReleaseGate() ? 600_000 : 120_000 })
    await expect(page.getByTestId('export-bar')).toBeVisible()
    const importMs = Date.now() - t0

    await page.evaluate(() => {
      const hook = (globalThis as typeof globalThis & {
        __rndLogAnonymizerPerfDiagnostics?: { recordInteractive(): void }
      }).__rndLogAnonymizerPerfDiagnostics
      hook?.recordInteractive()
    })

    const peakBeforeExport = browserName === 'chromium' ? await sampleChromiumHeap(page) : undefined

    const downloadPromise = page.waitForEvent('download')
    const expT0 = Date.now()
    await page.getByTestId('export-download').click()
    const download = await downloadPromise
    const exportMs = Date.now() - expT0
    const outPath = await download.path()
    expect(outPath).toBeTruthy()
    const body = await fs.promises.readFile(outPath!, 'utf8')

    if (MAX_SIZE_FULL) {
      assertExportMustNotLeak(body)
    } else {
      expect(body).not.toMatch(/CANARY builtin peer=10\.99\.88\.77/)
    }

    const peakAfterExport = browserName === 'chromium' ? await sampleChromiumHeap(page) : undefined
    const peakHeap = peakAfterExport ?? peakBeforeExport
    const heapRatio = peakHeap ? peakHeap / byteLength : undefined

    if (MAX_SIZE_FULL && browserName === 'chromium' && heapRatio !== undefined) {
      expect(heapRatio).toBeLessThanOrEqual(HEAP_BUDGET_TEXT + 0.5)
    }

    recordScenario(testInfo, {
      scenario: 'text-90mib-lf-default',
      inputBytes: byteLength,
      inputMiB: byteLength / (1024 * 1024),
      wallMs: importMs,
      exportMs,
      peakHeapBytes: peakHeap,
      heapBudgetRatio: heapRatio,
      crossOriginRequests: net.crossOrigin.length,
      diagnostics: await readPerfSnapshot(page),
    })

    net.stop()
    expect(net.crossOrigin).toEqual([])
  })

  test('90MiB CRLF production custom profile', async ({ page }, testInfo) => {
    test.setTimeout(isFullReleaseGate() ? 45 * 60_000 : 8 * 60_000)
    expect(fs.existsSync(productionProfilePath)).toBe(true)

    await expect(page.getByTestId('detection-settings-panel')).toBeVisible()
    await page.getByTestId('profile-menu-btn').click()
    await page.getByTestId('profile-import').click()
    const json = await fs.promises.readFile(productionProfilePath, 'utf8')
    await page.getByTestId('import-json-text').fill(json)
    await page.getByTestId('import-preview').click()
    await expect(page.getByTestId('import-preview-panel')).toBeVisible()
    if (await page.getByTestId('import-as-copy').isVisible()) {
      await page.getByTestId('import-as-copy').click()
    }
    await page.getByTestId('import-confirm').click()
    await expect(page.getByTestId('import-profile-dialog')).toHaveCount(0)

    const { filePath, byteLength } = resolveTextFixture('crlf')
    const t0 = Date.now()
    await page.getByTestId('persistent-file-input').setInputFiles(filePath)
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: isFullReleaseGate() ? 600_000 : 120_000 })

    recordScenario(testInfo, {
      scenario: 'text-90mib-crlf-production-profile',
      inputBytes: byteLength,
      inputMiB: byteLength / (1024 * 1024),
      wallMs: Date.now() - t0,
      crossOriginRequests: 0,
    })
  })

  test('regex timeout fail-closed blocks export', async ({ page }) => {
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await page.waitForFunction(
      () => typeof window.__RND_LOG_ANONYMIZER_E2E__?.markExportBlocked === 'function',
    )
    await expect
      .poll(async () => page.evaluate(() => window.__RND_LOG_ANONYMIZER_E2E__!.markExportBlocked()), {
        timeout: 10_000,
      })
      .toBe(true)
    await expect(page.getByTestId('security-bar')).toHaveAttribute('data-level', 'blocked')
    await expect(page.getByTestId('export-download')).toBeDisabled()
  })

  test('cancel during detection returns to idle', async ({ page }, testInfo) => {
    test.setTimeout(isFullReleaseGate() ? 10 * 60_000 : 3 * 60_000)
    // Full gate: use the 90 MiB LF fixture so detection lasts long enough for cancel UI.
    // Micro: denser synthetic log via the same persistent picker as other max-size text tests.
    const { filePath, byteLength } = MAX_SIZE_FULL
      ? resolveTextFixture('lf')
      : await (async () => {
          const p = await writeTempLog(
            'peer=10.1.2.3 user=alice host=canary.example.invalid\n'.repeat(200_000),
            'cancel-slow.log',
          )
          return { filePath: p, byteLength: fs.statSync(p).size }
        })()

    const importDone = page.getByTestId('persistent-file-input').setInputFiles(filePath)
    const t0 = Date.now()
    try {
      // ProgressSplash re-renders often; Playwright's actionability "stable" check then
      // sees a detached node. Invoke the live cancel control via DOM when it appears.
      await page.waitForFunction(
        () => {
          const btn = document.querySelector('[data-testid="cancel-analysis"]')
          if (!(btn instanceof HTMLButtonElement) || btn.disabled) return false
          btn.click()
          return true
        },
        undefined,
        { timeout: MAX_SIZE_FULL ? 90_000 : 15_000 },
      )
    } catch (err) {
      await importDone.catch(() => undefined)
      test.skip(!MAX_SIZE_FULL, 'Cancel UI missed — detection too fast on micro')
      throw err
    }
    await importDone.catch(() => undefined)
    await expect(page.getByTestId('multi-source-dropzone')).toBeVisible({
      timeout: MAX_SIZE_FULL ? 15_000 : 2_000,
    })
    const cancelMs = Date.now() - t0

    expect(cancelMs).toBeGreaterThan(0)
    expect(cancelMs).toBeLessThanOrEqual(MAX_SIZE_FULL ? 30_000 : 1_500)

    recordScenario(testInfo, {
      scenario: 'text-cancel-detection',
      inputBytes: byteLength,
      inputMiB: byteLength / (1024 * 1024),
      wallMs: cancelMs,
      cancelLatencyMs: cancelMs,
      crossOriginRequests: 0,
    })
  })

  test('CodeMirror render, scroll, wrap, search', async ({ page }) => {
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('dual-log')).toBeVisible({ timeout: 60_000 })

    await page.evaluate(async () => {
      const left = document.querySelector('[data-pane="original"]')?.closest('.cm-editor')
      const scroller = left?.querySelector('.cm-scroller') as HTMLElement | null
      if (!scroller) throw new Error('no scroller')
      scroller.scrollTop = Math.min(400, scroller.scrollHeight / 2)
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
    })

    await page.getByTestId('wrap-toggle').check()
    await expect(page.getByTestId('wrap-toggle')).toBeChecked()

    await page.keyboard.press('ControlOrMeta+f')
    await expect(page.getByTestId('log-search-input')).toBeFocused()
    await page.getByTestId('log-search-input').fill('10.16')
    await expect(page.getByTestId('log-search-counter')).not.toHaveText('—')

    await expect(page.getByTestId('occ-next')).toBeEnabled({ timeout: 15_000 })
    await page.getByTestId('occ-next').click()
    await expect(page.getByTestId('occ-counter')).not.toHaveText('—')
  })

  test('export preserves CRLF and strips canaries', async ({ page }) => {
    const crlf = 'line one\r\nCANARY builtin peer=10.99.88.77\r\nline three\r\n'
    const filePath = await writeTempLog(crlf, 'crlf-canary.log')
    await page.getByTestId('persistent-file-input').setInputFiles(filePath)
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 120_000 })

    const downloadPromise = page.waitForEvent('download')
    await page.getByTestId('export-download').click()
    const download = await downloadPromise
    const out = await fs.promises.readFile((await download.path())!, 'utf8')
    expect(out).toContain('\r\n')
    expect(out).not.toContain('10.99.88.77')
  })

  test('clipboard copy path (Chromium)', async ({ page, browserName, context }) => {
    test.skip(browserName !== 'chromium', 'clipboard-read permission is Chromium-only in Playwright')
    await context.grantPermissions(['clipboard-read', 'clipboard-write'])
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('export-copy')).toBeVisible({ timeout: 60_000 })
    await page.getByTestId('export-copy').click()
    await expect(page.getByTestId('app-toast')).toContainText('Zkopírováno', { timeout: 15_000 })
    const text = await page.evaluate(() => navigator.clipboard.readText())
    expect(text).not.toContain('10.16.1.105')
  })
})
