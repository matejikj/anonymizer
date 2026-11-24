import { test, expect } from '@playwright/test'
import { readFileSync, mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { loadUniversalFiles } from './helpers/loadFiles.ts'
import { generateClassicPcap } from '../pcap/fixtures/generate'
import { PCAP_WIRESHARK_VISUAL_SCENARIOS } from '../../src/pcap/ui/pcapWiresharkWireframe.ts'

const root = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(root, 'fixtures')

function ensurePcapFixture(): string {
  mkdirSync(fixturesDir, { recursive: true })
  const file = join(fixturesDir, 'wireshark-visual.pcap')
  if (!existsSync(file)) {
    try {
      writeFileSync(file, readFileSync(join(root, '../pcap/fixtures/generated/small-100.pcap')))
    } catch {
      writeFileSync(file, generateClassicPcap(40, 64))
    }
  }
  return file
}

async function prepare(page: import('@playwright/test').Page, theme: 'light' | 'dark', width = 1440, height = 900) {
  await page.setViewportSize({ width, height })
  await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' })
  await page.addInitScript((t) => {
    localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify(t))
    localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', JSON.stringify(true))
  }, theme)
  await page.goto('/')
  await loadUniversalFiles(page, ensurePcapFixture())
  await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 90_000 })
}

test.describe('PCAP Wireshark visual matrix (step 3)', () => {
  test.beforeEach(({ browserName }) => {
    test.skip(browserName !== 'chromium', 'Visual baselines are chromium-only')
  })

  test(`catalog lists ${PCAP_WIRESHARK_VISUAL_SCENARIOS.length} automated scenarios`, () => {
    expect(PCAP_WIRESHARK_VISUAL_SCENARIOS.length).toBeGreaterThanOrEqual(8)
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`desktop loaded ${theme}`, async ({ page }) => {
      await prepare(page, theme)
      await expect(page.getByTestId('pcap-comparison-workspace')).toHaveAttribute('data-layout', 'dual')
      await expect(page.getByTestId('pcap-packet-grid-original')).toHaveCount(1)
      await expect(page.getByTestId('pcap-packet-grid-anonymized')).toHaveCount(1)
      await expect(page.getByTestId('pcap-data-view-switch')).toHaveCount(0)
      await expect(page.getByTestId('pcap-byte-grid')).toHaveCount(2)
      await expect(page).toHaveScreenshot(`pcap-wireshark-desktop-${theme}.png`, { animations: 'disabled' })
    })
  }

  test('narrow layout light', async ({ page }) => {
    await prepare(page, 'light', 860, 700)
    await expect(page.getByTestId('pcap-capture-stage')).toHaveAttribute('data-layout', 'narrow')
    await expect(page).toHaveScreenshot('pcap-wireshark-narrow-light.png', { animations: 'disabled' })
  })

  test('single pane just below dual breakpoint', async ({ page }) => {
    await prepare(page, 'light', 1000, 800)
    await expect(page.getByTestId('pcap-comparison-workspace')).toHaveAttribute('data-layout', 'single')
    await expect(page.getByTestId('pcap-data-view-switch')).toBeVisible()
    await expect(page.locator('[data-testid^="pcap-packet-grid-"]')).toHaveCount(1)
  })

  test('invalid filter', async ({ page }) => {
    await prepare(page, 'light')
    await page.getByTestId('pcap-display-filter-input').fill('bad.field == 1')
    await expect(page.getByTestId('pcap-display-filter')).toHaveClass(/invalid/)
    await expect(page).toHaveScreenshot('pcap-wireshark-invalid-filter.png', { animations: 'disabled' })
  })

  test('empty filter result', async ({ page }) => {
    await prepare(page, 'light')
    await page.getByTestId('pcap-display-filter-input').fill('frame.number == 999999')
    await page.getByTestId('pcap-filter-apply').click()
    await expect(page.getByTestId('pcap-status-field')).toContainText(/Žádný paket|filter/i)
    await expect(page).toHaveScreenshot('pcap-wireshark-empty-filter.png', { animations: 'disabled' })
  })

  test('original data warning in single mode', async ({ page }) => {
    await prepare(page, 'light', 1000, 800)
    await page.getByTestId('pcap-data-view-original').click()
    await expect(page.getByTestId('pcap-original-warning')).toBeVisible()
    await expect(page).toHaveScreenshot('pcap-wireshark-original-warning.png', { animations: 'disabled' })
  })

  test('dual table guard requires one Original and one Anonymized grid', async ({ page }) => {
    await prepare(page, 'light', 1440, 900)
    await expect(page.getByTestId('pcap-packet-grid-original')).toHaveCount(1)
    await expect(page.getByTestId('pcap-packet-grid-anonymized')).toHaveCount(1)
    await expect(page.getByTestId('pcap-data-pane-original')).toContainText(/Original/)
    await expect(page.getByTestId('pcap-data-pane-anonymized')).toContainText(/Anonymized/)
    await expect(page.getByTestId('pcap-data-view-switch')).toHaveCount(0)
    await expect(page.locator('.pcap-tables--compare')).toHaveCount(0)
    await expect(page.locator('.pcap-bytes-panel__pre')).toHaveCount(0)
  })
})
