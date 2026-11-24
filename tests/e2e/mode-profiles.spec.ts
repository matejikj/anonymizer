import { test, expect } from '@playwright/test'
import { openDetectionSettings } from './helpers/openDetectionSettings.ts'
import { selectPcapLevel } from './helpers/selectPcapLevel.ts'
import { cs } from '../../src/i18n/cs'

test.describe('Detection settings profiles', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
  })

  test('settings panel shows text profile and PCAP level selects', async ({ page }) => {
    await openDetectionSettings(page)
    await expect(page.getByTestId('profile-selector')).toBeVisible()
    await expect(page.getByTestId('pcap-level-select')).toBeVisible()
    await expect(page.getByTestId('pcap-level-select-input')).toBeVisible()
    await expect(page.getByTestId('profile-select')).toContainText('RND Team')
  })

  test('text profile restores last selection after reload', async ({ page }) => {
    await openDetectionSettings(page)
    await page.getByTestId('profile-new').click()
    await expect(page.getByTestId('profile-select')).not.toHaveValue('rnd-team-production')
    const profileValue = await page.getByTestId('profile-select').inputValue()

    await page.reload()
    await openDetectionSettings(page)
    await expect(page.getByTestId('profile-select')).toHaveValue(profileValue)
  })

  test('PCAP level select offers exactly two options', async ({ page }) => {
    await openDetectionSettings(page)
    const options = page.getByTestId('pcap-level-select-input').locator('option')
    await expect(options).toHaveCount(2)
    await expect(options.nth(0)).toHaveText(
      new RegExp(cs.pcap.presets.diagnosticName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    )
    await expect(options.nth(1)).toHaveText(
      new RegExp(cs.pcap.presets.highPrivacyName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    )
  })

  test('changing PCAP level without capture does not open profile editor', async ({ page }) => {
    await selectPcapLevel(page, 'high-privacy')
    await expect(page.getByTestId('pcap-profile-editor')).toHaveCount(0)
    await expect(page.getByTestId('pcap-level-select-input')).toHaveValue('high-privacy')
  })
})
