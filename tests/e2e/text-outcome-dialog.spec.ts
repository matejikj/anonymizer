import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { loadUniversalFiles } from './helpers/loadFiles.ts'

for (const theme of ['light', 'dark'] as const) {
  test(`text outcome opens automatically, closes and reopens current results (${theme})`, async ({ page }) => {
    await page.setViewportSize({ width: theme === 'light' ? 1440 : 390, height: 950 })
    await page.addInitScript(value => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify(value))
    }, theme)
    await page.goto('/')
    await loadUniversalFiles(page, {
      name: 'outcome.log', mimeType: 'text/plain',
      buffer: Buffer.from('2026-10-22 INFO peer=10.1.2.3\n2026-10-22 INFO peer=10.1.2.3\n'),
    })
    const dialog = page.getByTestId('text-outcome-dialog')
    const panel = page.getByTestId('text-anonymization-outcome-panel')
    await expect(dialog).toBeVisible({ timeout: 60_000 })
    await expect(dialog.locator('h2')).toHaveCount(1)
    await expect(dialog.locator('h2')).toBeFocused()
    await page.keyboard.press('Shift+Tab')
    await expect(page.getByTestId('text-outcome-dialog-close')).toBeFocused()
    await expect(panel).toHaveAttribute('data-gate', 'AI_READY')
    await expect(dialog.getByTestId('text-anonymization-outcome-panel-encoding')).toContainText('UTF-8')
    const ipRow = dialog.locator('tbody tr').filter({ hasText: 'IP adresy' })
    await expect(ipRow.locator('td').nth(1)).toHaveText('1')
    await expect(ipRow.locator('td').nth(2)).toHaveText('2')
    await expect(ipRow.locator('td').nth(3)).toHaveText('1')
    await expect(page.getByTestId('workspace').getByTestId('text-anonymization-outcome-panel')).toHaveCount(0)
    // The table, incidents and close control remain reachable inside the modal.
    await page.keyboard.press('Tab')
    await expect(dialog.getByRole('region')).toBeFocused()
    await page.keyboard.press('Tab')
    await expect(dialog.locator('summary')).toBeFocused()
    await page.keyboard.press('Enter')
    await expect(dialog).toContainText('Žádné incidenty zpracování.')
    await page.keyboard.press('Tab')
    await expect(page.getByTestId('text-outcome-dialog-close')).toBeFocused()
    await page.keyboard.press('Tab')
    await expect(dialog.getByRole('region')).toBeFocused()
    const axe = await new AxeBuilder({ page }).include('[data-testid="text-outcome-dialog"]')
      .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()
    expect(axe.violations.filter(v => v.impact === 'critical' || v.impact === 'serious')).toEqual([])
    await page.screenshot({ path: `/tmp/text-outcome-dialog-${theme}.png` })
    await page.keyboard.press('Escape')
    await expect(dialog).toHaveCount(0)
    const opener = page.getByTestId('text-outcome-dialog-open')
    await expect(opener).toBeFocused()
    await expect(page.getByTestId('pane-original')).toBeVisible()
    await expect(page.getByTestId('pane-anonymized')).toBeVisible()
    if (theme === 'dark') await page.setViewportSize({ width: 1440, height: 950 })
    await page.getByTestId('category-switch-ip').click()
    await expect(page.getByTestId('security-bar')).toHaveAttribute('data-level', 'exposed')
    await expect(dialog).toHaveCount(0)
    await opener.click()
    await expect(ipRow.locator('td').nth(3)).toHaveText('0')
    await expect(panel).not.toHaveAttribute('data-gate', 'AI_READY')
    await page.getByTestId('text-outcome-dialog-close').click()
    await expect(opener).toBeFocused()
    // A new import gets its own outcome; a closed old dialog does not suppress it.
    await page.getByTestId('close-log').click()
    await expect(dialog).toHaveCount(0)
    await loadUniversalFiles(page, { name: 'clean.log', mimeType: 'text/plain', buffer: Buffer.from('Application ready\n') })
    await expect(dialog).toBeVisible()
    await expect(panel.locator('tbody tr')).toHaveCount(0)
    await page.mouse.click(2, 2)
    await expect(dialog).toHaveCount(0)
  })
}
