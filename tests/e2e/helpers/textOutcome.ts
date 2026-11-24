import { expect, type Page } from '@playwright/test'

/** Finish the result-dialog step before interacting with text editors or tools. */
export async function closeTextOutcomeDialog(page: Page): Promise<void> {
  await expect(page.getByTestId('text-outcome-dialog')).toBeVisible()
  await page.getByTestId('text-outcome-dialog-close').click()
  await expect(page.getByTestId('text-outcome-dialog')).toHaveCount(0)
}
