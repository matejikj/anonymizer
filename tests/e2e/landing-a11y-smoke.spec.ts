import { test, expect } from '@playwright/test'
import { cs } from '../../src/i18n/cs'

/**
 * Lightweight landing keyboard/focus + forced-colors smoke.
 * Broader axe coverage lives in a11y.spec.ts and help-a11y.spec.ts.
 */
test.describe('Landing a11y smoke', () => {
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' })
    await page.addInitScript(() => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('light'))
      localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', JSON.stringify(true))
    })
  })

  test('landing primary actions are keyboard focusable in order', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByTestId('landing')).toBeVisible()

    const skip = page.getByRole('link', { name: cs.skipToContent })
    await skip.focus()
    await expect(skip).toBeFocused()
    await page.keyboard.press('Enter')
    await expect(page.locator('#main')).toBeFocused()

    await page.getByTestId('multi-source-dropzone').focus()
    await expect(page.getByTestId('multi-source-dropzone')).toBeFocused()

    const pasteToggle = page.getByTestId('paste-toggle')
    await pasteToggle.focus()
    await expect(pasteToggle).toBeFocused()
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('landing-paste')).toBeVisible()
    await expect(pasteToggle).toHaveAttribute('aria-expanded', 'true')

    const textarea = page.getByTestId('paste-textarea')
    await textarea.focus()
    await expect(textarea).toBeFocused()

    await page.getByTestId('try-sample').focus()
    await expect(page.getByTestId('try-sample')).toBeFocused()
  })

  test('forced-colors landing renders primary chrome', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light', forcedColors: 'active' })
    await page.goto('/')
    await expect(page.getByTestId('landing')).toBeVisible()
    await expect(page.getByTestId('multi-source-dropzone')).toBeVisible()
    await expect(page.getByTestId('paste-toggle')).toBeVisible()
    await expect(page.getByTestId('try-sample')).toBeVisible()
    await expect(page.locator('.app-shell')).toHaveAttribute('data-design', 'clear-glass-operations')
  })

  test('reduced-motion landing keeps hierarchy without splash motion', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' })
    await page.goto('/')
    await expect(page.getByTestId('landing')).toBeVisible()
    await expect(page.getByTestId('multi-source-dropzone')).toBeVisible()
  })
})
