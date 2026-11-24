import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

test.describe('Design system gallery', () => {
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' })
    await page.goto('/gallery.html')
    await expect(page.getByTestId('design-system-gallery')).toBeVisible()
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'))
  })

  test('renders primitives and patterns; data surface has no backdrop blur', async ({ page }) => {
    await expect(page.getByTestId('gallery-buttons')).toBeVisible()
    await expect(page.getByTestId('gallery-fields')).toBeVisible()
    await expect(page.getByTestId('gallery-controls')).toBeVisible()
    await expect(page.getByTestId('gallery-surfaces')).toBeVisible()
    await expect(page.getByTestId('gallery-command-bar')).toBeVisible()

    const blur = await page.getByTestId('gallery-data-surface').evaluate((el) => {
      const s = getComputedStyle(el)
      return s.backdropFilter || (s as CSSStyleDeclaration & { webkitBackdropFilter?: string }).webkitBackdropFilter
    })
    expect(blur === 'none' || blur === '').toBe(true)
  })

  test('keyboard: tab reaches interactive controls', async ({ page }) => {
    await page.getByRole('button', { name: 'Primary' }).focus()
    await page.keyboard.press('Tab')
    const focused = await page.evaluate(() => document.activeElement?.tagName)
    expect(['BUTTON', 'INPUT', 'A']).toContain(focused)
  })

  test('axe has no serious/critical violations (light)', async ({ page }) => {
    const results = await new AxeBuilder({ page })
      .include('[data-testid="design-system-gallery"]')
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze()
    const blockers = results.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious')
    expect(blockers, JSON.stringify(blockers, null, 2)).toEqual([])
  })

  test.describe('visual baselines (chromium)', () => {
    test.beforeEach(({ browserName }) => {
      test.skip(browserName !== 'chromium', 'Screenshot baselines are chromium; axe runs tri-browser above')
    })

    for (const theme of ['light', 'dark'] as const) {
      test(`gallery screenshot ${theme}`, async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 1000 })
        await page.emulateMedia({ colorScheme: theme })
        await page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), theme)
        if (theme === 'dark') {
          await page.getByTestId('gallery-theme-toggle').click()
        }
        await expect(page).toHaveScreenshot(`gallery-${theme}.png`, {
          animations: 'disabled',
          fullPage: true,
        })
      })
    }

    test('forced-colors screenshot', async ({ page }) => {
      await page.setViewportSize({ width: 1440, height: 1000 })
      await page.emulateMedia({ colorScheme: 'light', forcedColors: 'active' })
      await expect(page).toHaveScreenshot('gallery-forced-colors.png', {
        animations: 'disabled',
        fullPage: true,
      })
    })
  })
})
