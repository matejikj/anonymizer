import type { Page } from '@playwright/test'

/** Detection controls live in the header — wait until they are ready. */
export async function openDetectionSettings(page: Page): Promise<void> {
  await page.getByTestId('detection-settings-panel').waitFor({ state: 'visible' })
  await page.getByTestId('profile-selector').waitFor({ state: 'visible' })
}
