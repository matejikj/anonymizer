import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { cs } from '../../src/i18n/cs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import fs from 'node:fs'

const here = path.dirname(fileURLToPath(import.meta.url))
const fixtures = path.join(here, 'fixtures')

async function assertNoCriticalA11y(
  page: import('@playwright/test').Page,
  label: string,
  options?: { include?: string; disableRules?: string[] },
) {
  let builder = new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
  if (options?.include) builder = builder.include(options.include)
  if (options?.disableRules?.length) builder = builder.disableRules(options.disableRules)
  const results = await builder.analyze()
  const blockers = results.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious')
  expect(blockers, `${label}: ${JSON.stringify(blockers, null, 2)}`).toEqual([])
}

function ensureFixtures() {
  fs.mkdirSync(fixtures, { recursive: true })
  const a = path.join(fixtures, 'multisource-a.log')
  const b = path.join(fixtures, 'multisource-b.log')
  if (!fs.existsSync(a)) fs.writeFileSync(a, 'peer 10.0.0.5 connected\n')
  if (!fs.existsSync(b)) fs.writeFileSync(b, 'server 10.0.0.5 ready\n')
  return { a, b }
}

test.describe('Multi-source correlation integration', () => {
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' })
    await page.addInitScript(() => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('light'))
    })
  })

  test('empty resolve CTA is keyboard reachable and axe-clean', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByTestId('empty-resolve-return-open')).toBeVisible()
    await page.getByTestId('empty-resolve-return-open').focus()
    await expect(page.getByTestId('empty-resolve-return-open')).toBeFocused()
    await assertNoCriticalA11y(page, 'empty-with-resolve-cta')
  })

  test('multi-file happy path: one confirm analysis, keyboard rail, export dialog, axe', async ({ page }) => {
    const { a, b } = ensureFixtures()
    await page.goto('/')
    await expect(page.getByTestId('multi-source-dropzone')).toBeVisible()

    const chooserPromise = page.waitForEvent('filechooser')
    await page.getByTestId('multi-source-dropzone').click()
    const chooser = await chooserPromise
    await chooser.setFiles([a, b])

    await expect(page.getByTestId('staging-source-list')).toBeVisible({ timeout: 30_000 })
    await assertNoCriticalA11y(page, 'correlation-staging')

    const confirm = page.getByRole('button', { name: cs.correlationStaging.confirm })
    await expect(confirm).toBeVisible()
    await confirm.click()

    await expect(
      page.getByTestId('correlation-workspace').or(page.getByTestId('correlation-progress')),
    ).toBeVisible({ timeout: 60_000 })

    await expect(page.getByTestId('correlation-workspace')).toBeVisible({ timeout: 90_000 })
    await assertNoCriticalA11y(page, 'correlation-workspace')

    const railAll = page.getByTestId('corr-rail-all')
    await railAll.focus()
    await expect(railAll).toBeFocused()
    await page.keyboard.press('ArrowDown')
    await expect(page.getByTestId('correlation-source-live')).toBeAttached()

    await expect(page.getByTestId('correlation-add-source')).toBeVisible()

    const exportBtn = page.getByTestId('correlation-export-open')
    await expect(exportBtn).toBeVisible()
    await exportBtn.focus()
    await expect(exportBtn).toBeFocused()
    await exportBtn.click()

    await expect(page.getByTestId('correlation-export-dialog')).toBeVisible()
    // Chromium channel Auto Dark Mode remaps modal pixels → axe color-contrast false positives
    // (same mitigation as tests/e2e/a11y.spec.ts help dialog).
    await assertNoCriticalA11y(page, 'correlation-export-dialog', {
      include: '[data-testid="correlation-export-dialog"]',
      disableRules: ['color-contrast'],
    })
    await page.keyboard.press('Escape')
  })

  test('dark theme staging/workspace axe gate', async ({ page }) => {
    const { a, b } = ensureFixtures()
    await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' })
    await page.addInitScript(() => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('dark'))
    })
    await page.goto('/')
    const chooserPromise = page.waitForEvent('filechooser')
    await page.getByTestId('multi-source-dropzone').click()
    const chooser = await chooserPromise
    await chooser.setFiles([a, b])
    await expect(page.getByTestId('staging-source-list')).toBeVisible({ timeout: 30_000 })
    await assertNoCriticalA11y(page, 'staging-dark', { disableRules: ['color-contrast'] })

    await page.getByRole('button', { name: cs.correlationStaging.confirm }).click()
    await expect(page.getByTestId('correlation-workspace')).toBeVisible({ timeout: 90_000 })
    await assertNoCriticalA11y(page, 'workspace-dark', { disableRules: ['color-contrast'] })
  })

  test('single-file import does not open multi-source staging', async ({ page }) => {
    const { a } = ensureFixtures()
    await page.goto('/')
    const chooserPromise = page.waitForEvent('filechooser')
    await page.getByTestId('multi-source-dropzone').click()
    const chooser = await chooserPromise
    await chooser.setFiles([a])
    await expect(page.getByTestId('staging-source-list')).toHaveCount(0)
    await expect(
      page.getByTestId('workspace-view').or(page.getByTestId('dual-log-view')).or(page.locator('.workspace')),
    ).toBeVisible({ timeout: 60_000 })
  })
})
