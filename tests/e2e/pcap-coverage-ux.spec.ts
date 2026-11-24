import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateClassicPcap } from '../pcap/fixtures/generate'
import { loadUniversalFiles } from './helpers/loadFiles.ts'
import { selectPcapLevel } from './helpers/selectPcapLevel.ts'

const root = dirname(fileURLToPath(import.meta.url))

function smallPcapBytes(): Buffer {
  try {
    return readFileSync(join(root, '../pcap/fixtures/generated/small-100.pcap'))
  } catch {
    return generateClassicPcap(20, 32)
  }
}

test.describe('PCAP coverage UX', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(window, 'showSaveFilePicker', {
        configurable: true,
        value: undefined,
      })
    })
  })

  test('diagnostic workspace: one primary export, summary, coverage dual columns, filter chips', async ({
    page,
  }) => {
    await page.goto('/')
    await loadUniversalFiles(page, {
      name: 'sample.pcap',
      mimeType: 'application/octet-stream',
      buffer: smallPcapBytes(),
    })
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('pcap-export')).toBeVisible()

    await page.getByTestId('pcap-open-inspector').click()
    await expect(page.getByTestId('pcap-inspector')).toBeVisible()
    await expect(page.getByTestId('pcap-overview-verdict')).toBeVisible()
    await page.getByTestId('pcap-inspector-tab-coverage').click()
    await expect(page.getByTestId('pcap-coverage-tab')).toBeVisible()
    await expect(page.getByTestId('pcap-coverage-legend')).toContainText('Rozpoznáno')
    await expect(page.getByTestId('pcap-coverage-legend')).toContainText('Chráněno')

    const protoBtn = page.locator('.pcap-coverage__proto-btn').first()
    if (await protoBtn.count()) {
      await protoBtn.click()
      const chips = page.getByTestId('pcap-filter-chips')
      if (await chips.count()) {
        await expect(chips).toBeVisible()
        await page.getByTestId('pcap-filter-chip-protocol').click()
        await expect(chips).toHaveCount(0)
      }
    }

    await page.getByTestId('pcap-inspector-tab-overview').click()
    await expect(page.getByTestId('pcap-overview-verdict')).toBeVisible()
  })

  test('high-privacy level selected before load is reflected in workspace', async ({ page }) => {
    await page.goto('/')
    await selectPcapLevel(page, 'high-privacy')
    await loadUniversalFiles(page, {
      name: 'hp.pcap',
      mimeType: 'application/octet-stream',
      buffer: smallPcapBytes(),
    })
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('pcap-level-select-input')).toHaveValue('high-privacy')
  })
})
