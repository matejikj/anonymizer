import { closeTextOutcomeDialog } from './helpers/textOutcome.ts'
import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { cs } from '../../src/i18n/cs'

async function assertNoCriticalA11y(
  page: import('@playwright/test').Page,
  label: string,
  options?: { include?: string; disableRules?: string[] },
) {
  let builder = new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
  if (options?.include) builder = builder.include(options.include)
  if (options?.disableRules?.length) builder = builder.disableRules(options.disableRules)
  const results = await builder.analyze()
  const blockers = results.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious')
  expect(blockers, `${label}: ${JSON.stringify(blockers, null, 2)}`).toEqual([])
}

test.describe('Accessibility', () => {
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' })
    await page.addInitScript(() => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('light'))
    })
  })

  test('empty shell has no serious/critical axe violations', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: cs.empty.landingLead })).toBeVisible()
    await assertNoCriticalA11y(page, 'empty')
  })

  test('workspace + help dialog have no serious/critical axe violations', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    await assertNoCriticalA11y(page, 'workspace')

    await page.getByTestId('help-open').click()
    await expect(page.getByTestId('help-panel')).toBeVisible()
    // Stage 6: contrast tokens use --color-ink; axe color-contrast stays enabled.
    await assertNoCriticalA11y(page, 'help', {
      include: '[data-testid="help-panel"]',
    })
    await page.getByTestId('help-close').click()
    await expect(page.getByTestId('help-panel')).toHaveCount(0)
  })

  test('Alt+Z toggles wrap and Esc closes help', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('wrap-toggle')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    const before = await page.getByTestId('wrap-toggle').isChecked()
    await page.keyboard.press('Alt+z')
    await expect(page.getByTestId('wrap-toggle')).toBeChecked({ checked: !before })

    await page.getByTestId('help-open').click()
    await expect(page.getByTestId('help-panel')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('help-panel')).toHaveCount(0)
  })
})
