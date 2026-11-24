import { closeTextOutcomeDialog } from '../../e2e/helpers/textOutcome.ts'
import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { cs } from '../../../src/i18n/cs.ts'
import { loadUniversalFiles } from '../../e2e/helpers/loadFiles.ts'
import { generateClassicPcap } from '../../pcap/fixtures/generate.ts'

async function assertNoCriticalA11y(
  page: import('@playwright/test').Page,
  label: string,
  options?: { colorScheme?: 'light' | 'dark' },
) {
  if (options?.colorScheme) {
    await page.emulateMedia({ colorScheme: options.colorScheme })
    await page.addInitScript((scheme) => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify(scheme))
    }, options.colorScheme)
    await page.reload()
  }

  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze()
  const blockers = results.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious')
  expect(blockers, `${label}: ${JSON.stringify(blockers, null, 2)}`).toEqual([])
}

test.describe('Max-size — accessibility release gate', () => {
  test('light theme empty + workspace axe', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' })
    await page.addInitScript(() => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('light'))
    })
    await page.goto('/')
    await expect(page.getByRole('heading', { name: cs.empty.landingLead })).toBeVisible()
    await assertNoCriticalA11y(page, 'max-size-light-empty')

    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    await assertNoCriticalA11y(page, 'max-size-light-workspace')
  })

  test('dark theme empty + PCAP workspace axe', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' })
    await page.addInitScript(() => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('dark'))
    })
    await page.goto('/')
    await expect(page.getByTestId('multi-source-dropzone')).toBeVisible()
    await assertNoCriticalA11y(page, 'max-size-dark-empty')

    await loadUniversalFiles(page, {
      name: 'max-size-dark.pcap',
      mimeType: 'application/octet-stream',
      buffer: generateClassicPcap(20, 32),
    })
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 60_000 })
    await assertNoCriticalA11y(page, 'max-size-dark-pcap-workspace')
  })
})
