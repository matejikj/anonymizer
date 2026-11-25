import { test, expect } from '@playwright/test'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { loadUniversalFiles } from './helpers/loadFiles'
import { selectPcapLevel } from './helpers/selectPcapLevel'

for (const name of ['MP_Pro_RGW_test_20261120a.pcap.gz', 'MP_Pro_RGW_test_20261120b.pcap.gz']) {
  const path = fileURLToPath(new URL(`../../logs/${name}`, import.meta.url))
  test(`${name}: gzip import shows an informational outcome`, async ({ page }) => {
    test.skip(!existsSync(path), 'Local customer capture is absent')
    test.setTimeout(240_000)
    await page.setViewportSize({ width: 1440, height: 1000 })
    await page.goto('/')
    await selectPcapLevel(page, 'diagnostic')
    await loadUniversalFiles(page, path)
    const panel = page.getByTestId('pcap-workspace-outcome')
    await expect(panel).toBeVisible({ timeout: 180_000 })
    await expect(panel).toHaveAttribute('data-gate', /^(AI_READY|AI_READY_WITH_GAPS)$/)
    await expect(panel).not.toContainText(/ověřte|zkontrolujte|k prověření|Před předáním AI je potřeba kontrola|NOT AI READY/i)
    await expect(panel).toContainText('Jak chráníme data')
    await expect(panel).toContainText('Vlastnosti výstupu')
    const decision = panel.locator('.anonymization-outcome__decision')
    expect(await decision.evaluate(el => getComputedStyle(el).getPropertyValue('--outcome-tone').trim()))
      .toBe(await decision.evaluate(el => getComputedStyle(el).getPropertyValue('--color-ok').trim()))
    await page.getByTestId('pcap-outcome-dialog').screenshot({ path: `/tmp/${name}.outcome.png` })
  })
}
