import { test, expect } from '@playwright/test'
import { REFERENCE_VIEWPORT } from '../../src/styles/referenceCompositions.ts'

async function prepare(page: import('@playwright/test').Page, theme: 'light' | 'dark') {
  await page.setViewportSize(REFERENCE_VIEWPORT)
  await page.emulateMedia({ colorScheme: theme })
  await page.addInitScript((t) => {
    localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify(t))
    localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', JSON.stringify(true))
  }, theme)
}

test.describe('Clear Glass Operations visual baseline', () => {
  test.beforeEach(({ browserName }) => {
    test.skip(browserName !== 'chromium', 'Chromium-only screenshot baselines; visual-matrix covers full screen matrix')
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`landing ${theme} @ 1440×1000`, async ({ page }) => {
      await prepare(page, theme)
      await page.goto('/')
      await expect(page.getByTestId('landing')).toBeVisible()
      await expect(page.getByTestId('app-header')).toBeVisible()
      await expect(page.getByTestId('first-visit-tour')).toHaveCount(0)
      await expect(page.locator('.app-shell')).toHaveAttribute('data-design', 'clear-glass-operations')
      await expect(page.locator('.app-shell')).toHaveAttribute('data-density', 'compact')
      await expect(page).toHaveScreenshot(`visual-baseline-landing-${theme}.png`, {
        animations: 'disabled',
      })
    })

    test(`text workspace ${theme} @ 1440×1000`, async ({ page }) => {
      await prepare(page, theme)
      await page.goto('/')
      await expect(page.getByTestId('landing')).toBeVisible()
      await page.getByTestId('try-sample').click()
      await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
      await expect(page.getByTestId('dual-log')).toBeVisible()
      await expect(page.locator('.app-shell')).toHaveAttribute('data-density', 'compact')
      await expect(page).toHaveScreenshot(`visual-baseline-text-workspace-${theme}.png`, {
        animations: 'disabled',
      })
    })
  }
})
