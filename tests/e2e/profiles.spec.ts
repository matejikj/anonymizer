import { test, expect } from '@playwright/test'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema.ts'
import { serializeRulesetConfig } from '../../src/domain/rulesetValidate.ts'
import { openDetectionSettings } from './helpers/openDetectionSettings.ts'

test.describe('JSON profiles', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
    await openDetectionSettings(page)
    await expect(page.getByTestId('profile-selector')).toBeVisible()
  })

  test('selector is visible and can open editor', async ({ page }) => {
    await page.getByTestId('profile-new').click()
    await page.getByTestId('profile-edit').click()
    await expect(page.getByTestId('profile-editor')).toBeVisible()
    await page.getByTestId('profile-name').fill('Můj profil')
    await page.getByTestId('profile-editor-save').click()
    await expect(page.getByTestId('profile-editor')).toHaveCount(0)
    await expect(page.getByTestId('profile-select')).toContainText('Můj profil')
  })

  test('only built-in default is undeletable; user profile can be deleted', async ({ page }) => {
    await page.getByTestId('profile-menu-btn').click()
    await expect(page.getByTestId('profile-delete')).toBeDisabled()
    await page.keyboard.press('Escape')
    await page.getByTestId('profile-new').click()
    await expect(page.getByTestId('profile-select')).not.toHaveValue('rnd-team-production')
    await page.getByTestId('profile-menu-btn').click()
    await expect(page.getByTestId('profile-delete')).toBeEnabled()
    await page.getByTestId('profile-delete').click()
    await expect(page.getByTestId('profile-select')).toHaveValue('rnd-team-production')
  })

  test('import valid JSON as copy and export downloads .rnd-log-anonymizer.json', async ({ page }) => {
    const cfg = createDefaultRulesetConfig()
    // Collide with the built-in active profile so the copy/replace choice appears.
    cfg.profile.id = 'rnd-team-production'
    cfg.profile.name = 'Imported default twin'
    cfg.profile.rules.push({
      id: 'ticket',
      name: 'Ticket',
      enabled: true,
      kind: 'regex',
      pattern: 'TICKET-[0-9]{6}',
      caseSensitive: false,
      category: 'internal-id',
      replacement: { kind: 'generated' },
    })
    const json = serializeRulesetConfig(cfg)

    await page.getByTestId('profile-menu-btn').click()
    await page.getByTestId('profile-import').click()
    await expect(page.getByTestId('import-profile-dialog')).toBeVisible()
    await page.getByTestId('import-json-text').fill(json)
    await page.getByTestId('import-preview').click()
    await expect(page.getByTestId('import-preview-panel')).toBeVisible()
    await expect(page.getByTestId('import-as-copy')).toBeVisible()
    await page.getByTestId('import-confirm').click()
    await expect(page.getByTestId('import-profile-dialog')).toHaveCount(0)
    await expect(page.getByTestId('profile-select')).toContainText('import')

    const downloadPromise = page.waitForEvent('download')
    await page.getByTestId('profile-menu-btn').click()
    await page.getByTestId('profile-export').click()
    // May show warn dialog if literals — this profile is regex-only
    const download = await downloadPromise
    expect(download.suggestedFilename()).toMatch(/\.rnd-log-anonymizer\.json$/)
  })

  test('invalid JSON does not change active profile', async ({ page }) => {
    await expect(page.getByTestId('profile-select')).not.toHaveValue('')
    const before = await page.getByTestId('profile-select').inputValue()
    await page.getByTestId('profile-menu-btn').click()
    await page.getByTestId('profile-import').click()
    await page.getByTestId('import-json-text').fill('{ "schemaVersion": 1 ')
    await page.getByTestId('import-preview').click()
    await expect(page.getByTestId('import-error')).toBeVisible()
    await page.getByTestId('import-profile-dialog').getByRole('button', { name: 'Zrušit' }).click()
    await expect(page.getByTestId('profile-select')).toHaveValue(before)
  })

  test('adding a rule marks profile dirty until save', async ({ page }) => {
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await page.getByTestId('review-tab-rules').click()
    await page.getByTestId('add-rule').click()
    await page.getByTestId('rule-pattern').fill('LoginController')
    await page.getByTestId('rule-save').click()
    await expect(page.getByTestId('rule-form')).toHaveCount(0, { timeout: 60_000 })
    await openDetectionSettings(page)
    await expect(page.getByTestId('profile-dirty')).toBeVisible()
    await page.getByTestId('profile-save').click()
    await expect(page.getByTestId('profile-dirty')).toHaveCount(0)
  })
})
