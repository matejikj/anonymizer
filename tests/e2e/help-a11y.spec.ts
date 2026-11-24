import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { cs } from '../../src/i18n/cs'

/**
 * HelpPanel keyboard + axe (contrast enabled).
 */
test.describe('HelpPanel accessibility', () => {
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' })
    await page.addInitScript(() => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('light'))
      localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', JSON.stringify(true))
    })
  })

  test('help focus trap, Escape restore, and axe without color-contrast carve-out', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: cs.empty.landingLead })).toBeVisible()

    const helpOpen = page.getByTestId('help-open')
    await helpOpen.focus()
    await helpOpen.click()
    await expect(page.getByTestId('help-panel')).toBeVisible()

    // Autofocus lands on the dialog title; Tab reaches the scrollable body.
    const title = page.getByTestId('help-panel').locator('h2')
    await expect(title).toBeFocused()
    await page.keyboard.press('Tab')
    const body = page.getByTestId('help-panel-body')
    await expect(body).toBeVisible()

    const axe = await new AxeBuilder({ page })
      .include('[data-testid="help-panel"]')
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
      .analyze()
    const blockers = axe.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious')
    expect(blockers, JSON.stringify(blockers, null, 2)).toEqual([])

    await page.keyboard.press('Escape')
    await expect(page.getByTestId('help-panel')).toHaveCount(0)
    await expect
      .poll(async () => helpOpen.evaluate((el) => el === document.activeElement), { timeout: 5_000 })
      .toBe(true)

    // Re-open after restore (activate the restored trigger)
    await helpOpen.press('Enter')
    await expect(page.getByTestId('help-panel')).toBeVisible()
    await page.getByTestId('help-close').click()
    await expect(page.getByTestId('help-panel')).toHaveCount(0)
  })
})
