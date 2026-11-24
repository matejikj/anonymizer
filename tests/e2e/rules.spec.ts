import { closeTextOutcomeDialog } from './helpers/textOutcome.ts'
import { test, expect } from '@playwright/test'
import { cs } from '../../src/i18n/cs.ts'

const csBusy = cs.review.recomputing

test.describe('Custom rules', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    await page.getByTestId('review-tab-rules').click()
    await expect(page.getByTestId('custom-rules')).toBeVisible()
  })

  test('adds literal rule with live preview and applies to anonymized pane', async ({
    page,
  }) => {
    await page.getByTestId('add-rule').click()
    await expect(page.getByTestId('rule-form')).toBeVisible()

    await page.getByTestId('rule-kind-literal').click()
    await page.getByTestId('rule-pattern').fill('LoginController')
    await expect(page.getByTestId('rule-name')).not.toHaveValue('')
    await expect(page.getByTestId('rule-preview')).toBeVisible()
    await expect(page.getByTestId('rule-match-count')).toContainText('1')
    await expect(page.getByTestId('rule-sample').first()).toBeVisible()

    await page.getByTestId('rule-save').click()
    await expect(page.getByTestId('rule-form')).toHaveCount(0, { timeout: 60_000 })
    await expect(page.locator('[data-testid^="rule-row-"]').first()).toBeVisible()

    const anon = page.locator('[data-pane="anonymized"]')
    await expect(anon).toBeVisible()
    await expect(anon).not.toContainText('LoginController')
  })

  test('adds regex rule and blocks invalid / zero-length regex', async ({ page }) => {
    await page.getByTestId('add-rule').click()
    await page.getByTestId('rule-kind-regex').click()

    await page.getByTestId('rule-pattern').fill('/bad/')
    await expect(page.getByTestId('rule-error')).toBeVisible()
    await expect(page.getByTestId('rule-save')).toBeDisabled()

    await page.getByTestId('rule-pattern').fill('a*')
    await expect(page.getByTestId('rule-error')).toBeVisible()
    await expect(page.getByTestId('rule-save')).toBeDisabled()

    await page.getByTestId('rule-pattern').fill('JwtUtil')
    await expect(page.getByTestId('rule-error')).toHaveCount(0)
    await expect(page.getByTestId('rule-save')).toBeEnabled()
    await page.getByTestId('rule-save').click()
    await expect(page.getByTestId('rule-form')).toHaveCount(0, { timeout: 60_000 })
    await expect(page.locator('[data-pane="anonymized"]')).not.toContainText('JwtUtil')
  })

  test('edit, duplicate, toggle, delete with undo', async ({ page }) => {
    const initialRuleCount = await page.locator('[data-testid^="rule-row-"]').count()
    await page.getByTestId('add-rule').click()
    await page.getByTestId('rule-pattern').fill('TenantService')
    await page.getByTestId('rule-name').fill('Tenant label')
    await page.getByTestId('rule-save').click()
    await expect(page.getByTestId('rule-form')).toHaveCount(0, { timeout: 60_000 })

    const row = page.locator('[data-testid^="rule-row-"]').filter({ hasText: 'Tenant label' })
    await expect(row).toContainText('Tenant label')
    const ruleId = (await row.getAttribute('data-testid'))!.replace('rule-row-', '')

    await page.getByTestId(`rule-edit-${ruleId}`).click()
    await expect(page.getByTestId('rule-form')).toBeVisible()
    await page.getByTestId('rule-name').fill('Tenant edited')
    await expect(page.getByTestId('rule-name')).toHaveValue('Tenant edited')
    await page.getByTestId('rule-save').click()
    await expect(page.getByTestId('rule-form')).toHaveCount(0, { timeout: 60_000 })
    await expect(page.getByTestId(`rule-row-${ruleId}`)).toContainText('Tenant edited')

    const enabled = page.getByTestId(`rule-enabled-${ruleId}`)
    await expect(enabled).toBeChecked()
    await enabled.setChecked(false)
    await expect(enabled).not.toBeChecked({ timeout: 60_000 })
    await expect(page.getByTestId('review-panel')).not.toContainText(csBusy, {
      timeout: 60_000,
    })
    // Disabled rule should leave original visible again
    await expect(page.locator('[data-pane="anonymized"]')).toContainText('TenantService', {
      timeout: 60_000,
    })

    await enabled.setChecked(true)
    await expect(enabled).toBeChecked({ timeout: 60_000 })
    await expect(page.getByTestId('review-panel')).not.toContainText(csBusy, {
      timeout: 60_000,
    })
    await expect(page.locator('[data-pane="anonymized"]')).not.toContainText('TenantService', {
      timeout: 60_000,
    })

    await page.getByTestId(`rule-dup-${ruleId}`).click()
    await expect(page.locator('[data-testid^="rule-row-"]')).toHaveCount(initialRuleCount + 2, { timeout: 60_000 })

    await page.getByTestId(`rule-delete-${ruleId}`).click()
    await expect(page.getByTestId('app-toast')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId(`rule-row-${ruleId}`)).toHaveCount(0)
    await page.getByTestId('toast-undo').click()
    await expect(page.getByTestId(`rule-row-${ruleId}`)).toBeVisible({ timeout: 60_000 })
  })

  test('Ctrl/Cmd+Shift+R opens custom rules form', async ({ page }) => {
    await page.getByTestId('review-tab-overview').click()
    const isMac = process.platform === 'darwin'
    await page.keyboard.press(isMac ? 'Meta+Shift+R' : 'Control+Shift+R')
    await expect(page.getByTestId('review-tab-rules')).toHaveAttribute('aria-selected', 'true')
    await expect(page.getByTestId('rule-form')).toBeVisible()
  })

  test('progressive disclosure hides advanced options by default', async ({ page }) => {
    await page.getByTestId('add-rule').click()
    await expect(page.getByTestId('rule-advanced')).toHaveCount(0)
    await page.getByTestId('rule-more-options').click()
    await expect(page.getByTestId('rule-advanced')).toBeVisible()
    await expect(page.getByTestId('rule-category')).toBeVisible()
    await expect(page.getByTestId('rule-case-sensitive')).toBeVisible()
  })
})
