import { closeTextOutcomeDialog } from './helpers/textOutcome.ts'
import { test, expect } from '@playwright/test'
import { REFERENCE_VIEWPORT } from '../../src/styles/referenceCompositions.ts'

/**
 * Clear Glass hierarchy smoke — tri-browser Clear Glass hierarchy smoke (no pixel baselines).
 * Chromium keeps deterministic screenshots in visual-baseline/visual-matrix specs; Firefox/WebKit
 * assert shell hierarchy and primary CTA so glass fallback cannot reorder chrome.
 */
async function prepare(page: import('@playwright/test').Page, theme: 'light' | 'dark') {
  await page.setViewportSize(REFERENCE_VIEWPORT)
  await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' })
  await page.addInitScript((t) => {
    localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify(t))
    localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', JSON.stringify(true))
  }, theme)
}

test.describe('Clear Glass Operations hierarchy (tri-browser)', () => {
  for (const theme of ['light', 'dark'] as const) {
    test(`landing hierarchy ${theme}`, async ({ page }) => {
      await prepare(page, theme)
      await page.goto('/')
      await expect(page.locator('.app-shell')).toHaveAttribute('data-design', 'clear-glass-operations')
      await expect(page.getByTestId('landing')).toBeVisible()
      await expect(page.getByTestId('app-header')).toBeVisible()
      await expect(page.getByTestId('multi-source-dropzone')).toBeVisible()
      await expect(page.getByTestId('multi-source-dropzone')).toHaveClass(/dropzone--hero/)
      await expect(page.getByTestId('empty-resolve-return-open')).not.toHaveClass(/btn--primary/)
      await expect(page.getByTestId('choose-file')).toHaveCount(0)
    })

    test(`text workspace hierarchy ${theme}`, async ({ page }) => {
      await prepare(page, theme)
      await page.goto('/')
      await page.getByTestId('try-sample').click()
      await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
      await closeTextOutcomeDialog(page)
      await expect(page.getByTestId('dual-log')).toBeVisible()
      await expect(page.locator('.app-shell')).toHaveAttribute('data-density', 'compact')
      // Data plane must remain opaque class (no glass on editors)
      await expect(page.locator('[data-pane="original"]')).toBeVisible()
      await expect(page.locator('[data-pane="anonymized"]')).toBeVisible()
    })
  }
})
