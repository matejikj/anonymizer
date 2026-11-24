import { test, expect } from '@playwright/test'

test.describe('Review panel findings', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('review-panel')).toBeVisible()
  })

  test('overview lists categories with master switches', async ({ page }) => {
    await expect(page.getByTestId('review-tab-overview')).toHaveAttribute(
      'aria-selected',
      'true',
    )
    await expect(page.getByTestId('review-overview')).toBeVisible()
    const switches = page.locator('[data-testid^="category-switch-"]')
    await expect(switches.first()).toBeVisible()
    expect(await switches.count()).toBeGreaterThan(0)
  })

  test('entity toggle updates anonymized pane and security bar', async ({ page }) => {
    await page.getByTestId('review-tab-entities').click()
    await expect(page.getByTestId('entity-list')).toBeVisible()

    await expect(page.getByTestId('security-bar')).toHaveAttribute('data-level', 'ok')

    const firstSwitch = page.locator('[data-testid^="entity-switch-"]').first()
    await expect(firstSwitch).toBeChecked()
    await firstSwitch.click()
    await expect(firstSwitch).not.toBeChecked()

    await expect(page.getByTestId('security-bar')).toHaveAttribute('data-level', 'exposed')

    // Original of disabled entity should appear in anonymized pane DOM
    const anon = page.locator('[data-pane="anonymized"]')
    // Re-enable
    await firstSwitch.click()
    await expect(firstSwitch).toBeChecked()
    await expect(page.getByTestId('security-bar')).toHaveAttribute('data-level', 'ok')
    await expect(anon).toBeVisible()
  })

  test('category master off exposes originals and restores individuals', async ({ page }) => {
    const ipSwitch = page.getByTestId('category-switch-ip')
    await expect(ipSwitch).toBeChecked()

    // Disable one IP entity individually first
    await page.getByTestId('review-tab-entities').click()
    await page.getByTestId('entity-filter').selectOption('ip')
    const entitySwitch = page.locator('[data-testid^="entity-switch-ip::"]').first()
    await expect(entitySwitch).toBeVisible()
    await entitySwitch.click()
    await expect(entitySwitch).not.toBeChecked()

    await page.getByTestId('review-tab-overview').click()
    await ipSwitch.click()
    await expect(ipSwitch).not.toBeChecked()
    await expect(page.getByTestId('security-bar')).toHaveAttribute('data-level', 'exposed')

    // Turn category back on — individual off should remain
    await ipSwitch.click()
    await expect(ipSwitch).toBeChecked()
    await page.getByTestId('review-tab-entities').click()
    await page.getByTestId('entity-filter').selectOption('ip')
    await expect(entitySwitch).not.toBeChecked()
    await expect(page.getByTestId('security-bar')).toHaveAttribute('data-level', 'exposed')
  })

  test('search filters entity list and jump highlights occurrence', async ({ page }) => {
    await page.getByTestId('review-tab-entities').click()
    await page.getByTestId('entity-search').fill('10.16')
    const rows = page.locator('[data-testid^="entity-row-"]')
    await expect(rows.first()).toBeVisible()
    const count = await rows.count()
    expect(count).toBeGreaterThan(0)
    expect(count).toBeLessThan(20)

    await rows.first().locator('button.entity-list__jump').click()
    await expect(page.locator('.cm-sync-match').first()).toBeVisible()
  })
})
