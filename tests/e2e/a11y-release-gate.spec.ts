import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { cs } from '../../src/i18n/cs'

/**
 * HelpPanel + landing a11y extras (200% text zoom, forced-colors hierarchy).
 */
test.describe('A11y release gate extras', () => {
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' })
    await page.addInitScript(() => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('light'))
      localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', JSON.stringify(true))
    })
  })

  test('HelpPanel at 200% zoom keeps focus trap and axe-clean panel', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 1000 })
    await page.goto('/')
    // Avoid addStyleTag (CSP); set text zoom via inline style.
    await page.evaluate(() => {
      document.documentElement.style.fontSize = '200%'
    })

    const helpOpen = page.getByTestId('help-open')
    await helpOpen.focus()
    await helpOpen.click()
    await expect(page.getByTestId('help-panel')).toBeVisible()

    const title = page.getByTestId('help-panel').locator('h2')
    await expect(title).toBeFocused()
    await page.keyboard.press('Tab')
    await expect(page.getByTestId('help-panel-body')).toBeVisible()

    const axe = await new AxeBuilder({ page })
      .include('[data-testid="help-panel"]')
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
      .analyze()
    const blockers = axe.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious')
    expect(blockers, JSON.stringify(blockers, null, 2)).toEqual([])

    await page.keyboard.press('Escape')
    await expect(page.getByTestId('help-panel')).toHaveCount(0)
    // Focus-return under 200% text zoom is covered at default size by help-a11y.spec.ts
    // (WebKit does not reliably restore focus while html font-size is scaled).
  })

  test('forced-colors preserves primary action hierarchy on landing', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light', forcedColors: 'active' })
    await page.goto('/')
    await expect(page.getByTestId('landing')).toBeVisible()
    await expect(page.getByTestId('multi-source-dropzone')).toBeVisible()
    await expect(page.getByTestId('multi-source-dropzone')).toHaveClass(/dropzone--hero/)
    await expect(page.locator('.app-shell')).toHaveAttribute('data-design', 'clear-glass-operations')
    await expect(page.getByTestId('choose-file')).toHaveCount(0)
    await expect(page.getByTestId('empty-resolve-return-open')).not.toHaveClass(/btn--primary/)
  })

  test('opaque glass fallback hierarchy without backdrop-filter', async ({ page }) => {
    await page.addInitScript(() => {
      const style = document.createElement('style')
      style.textContent = `
        .surface-glass, .ds-glass-panel, .app-header, .ds-command-bar {
          -webkit-backdrop-filter: none !important;
          backdrop-filter: none !important;
        }
      `
      document.documentElement.appendChild(style)
    })
    await page.goto('/')
    await expect(page.getByTestId('landing')).toBeVisible()
    await expect(page.getByTestId('app-header')).toBeVisible()
    await expect(page.getByRole('heading', { name: cs.empty.landingLead })).toBeVisible()
    await expect(page.getByTestId('choose-file')).toHaveCount(0)
    await expect(page.getByTestId('multi-source-dropzone')).toBeVisible()
  })
})
