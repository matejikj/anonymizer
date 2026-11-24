import { test, expect } from '@playwright/test'

/**
 * After cancel/reset, a new import succeeds without reload.
 */
test.describe('Session lifecycle reset and reimport', () => {
  test('close log then sample import works without reload', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })

    await page.getByTestId('close-log').click()
    await expect(page.getByTestId('landing')).toBeVisible({ timeout: 15_000 })

    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('dual-log')).toBeVisible()
  })
})
