import type { Page } from '@playwright/test'
import { openDetectionSettings } from './openDetectionSettings.ts'

export async function selectPcapLevel(
  page: Page,
  level: 'diagnostic' | 'high-privacy',
): Promise<void> {
  await openDetectionSettings(page)
  await page.getByTestId('pcap-level-select-input').selectOption(level)
}
