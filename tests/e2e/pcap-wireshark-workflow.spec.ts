import { test, expect } from '@playwright/test'
import { readFileSync, mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { loadUniversalFiles } from './helpers/loadFiles.ts'
import { generateClassicPcap } from '../pcap/fixtures/generate'

const root = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(root, 'fixtures')

function ensurePcapFixture(): string {
  mkdirSync(fixturesDir, { recursive: true })
  const file = join(fixturesDir, 'wireshark-workflow.pcap')
  if (!existsSync(file)) {
    try {
      writeFileSync(file, readFileSync(join(root, '../pcap/fixtures/generated/small-100.pcap')))
    } catch {
      writeFileSync(file, generateClassicPcap(30, 48))
    }
  }
  return file
}

async function loadPcap(page: import('@playwright/test').Page) {
  await page.addInitScript(() => {
    localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('light'))
    localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', JSON.stringify(true))
  })
  await page.goto('/')
  await loadUniversalFiles(page, ensurePcapFixture())
  await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 90_000 })
}

test.describe('PCAP Wireshark workflow (step 3)', () => {
  test('open → filter → select → bytes sync → dual layout guard', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await loadPcap(page)

    await expect(page.getByTestId('pcap-display-filter')).toBeVisible()
    await expect(page.getByTestId('pcap-comparison-workspace')).toHaveAttribute('data-layout', 'dual')
    await expect(page.getByTestId('pcap-packet-grid-original')).toHaveCount(1)
    await expect(page.getByTestId('pcap-packet-grid-anonymized')).toHaveCount(1)
    await expect(page.getByTestId('pcap-byte-grid')).toHaveCount(2)
    await expect(page.locator('.pcap-tables--compare')).toHaveCount(0)

    const filterInput = page.getByTestId('pcap-display-filter-input')
    await filterInput.fill('frame.number >= 1')
    await page.getByTestId('pcap-filter-apply').click()
    await expect(page.getByTestId('pcap-filter-applied')).toBeVisible()

    await page.getByTestId('pcap-packet-grid-anonymized').click()
    await page.keyboard.press('ArrowDown')
    await expect(page.getByTestId('pcap-packet-details').first()).toBeVisible()
    await expect(page.getByTestId('pcap-dissection-tree').first()).toBeVisible()

    const tree = page.getByTestId('pcap-dissection-tree').first()
    const firstNode = tree.locator('[data-offset]').first()
    if (await firstNode.count()) {
      await firstNode.click()
      await expect(page.getByTestId('pcap-byte-grid').first().locator('.is-highlighted')).toHaveCount(
        { timeout: 5000, minimum: 1 },
      )
    }

    await page.getByTestId('pcap-status-bar').waitFor({ state: 'visible' }).catch(() => {})
    await expect(page.getByTestId('pcap-status-bar')).toBeVisible()
    await expect(page.getByTestId('pcap-export')).toBeVisible()
  })

  test('invalid filter shows error state without hiding workspace', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await loadPcap(page)
    await page.getByTestId('pcap-display-filter-input').fill('not_a_field == 1')
    await expect(page.getByTestId('pcap-display-filter')).toHaveClass(/invalid/)
    await expect(page.getByTestId('pcap-packet-grid-anonymized')).toBeVisible()
  })

  test('original pane focus and dual labels', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await loadPcap(page)
    await page.getByTestId('pcap-data-pane-original').click()
    await expect(page.getByTestId('pcap-data-pane-original')).toHaveAttribute('data-focused', 'true')
    await expect(page.getByTestId('pcap-status-data-view')).toContainText(/Original/i)
  })

  test('single mode keeps Original|Anonymized switch', async ({ page }) => {
    await page.setViewportSize({ width: 1000, height: 800 })
    await loadPcap(page)
    await expect(page.getByTestId('pcap-comparison-workspace')).toHaveAttribute('data-layout', 'single')
    await page.getByTestId('pcap-data-view-original').click()
    await expect(page.getByTestId('pcap-original-warning')).toBeVisible()
  })
})
