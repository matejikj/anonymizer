/**
 * Correlation — tri-browser release gate.
 * Covers import → review → export dialog + resolve-only entry.
 * Never logs originals, aliases, or passphrases into the JSON reporter payload.
 */
import { test, expect } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { cs } from '../../../src/i18n/cs.ts'
import { chooseMappingBundleFromLanding } from '../../e2e/helpers/mappingBundleFixture.ts'

const here = path.dirname(fileURLToPath(import.meta.url))
const fixtures = path.join(here, '../fixtures/correlation')

function ensureFixtures() {
  fs.mkdirSync(fixtures, { recursive: true })
  const a = path.join(fixtures, 'dot.log')
  const b = path.join(fixtures, 'as.log')
  if (!fs.existsSync(a)) fs.writeFileSync(a, 'peer 10.0.0.5 connected\n')
  if (!fs.existsSync(b)) fs.writeFileSync(b, 'server 10.0.0.5 ready\n')
  return { a, b }
}

test.describe('Correlation release gate', () => {
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' })
    await page.addInitScript(() => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('light'))
    })
  })

  test('single-file text workflow does not open correlation staging', async ({ page }) => {
    const { a } = ensureFixtures()
    await page.goto('/')
    const chooserPromise = page.waitForEvent('filechooser')
    await page.getByTestId('multi-source-dropzone').click()
    const chooser = await chooserPromise
    await chooser.setFiles([a])
    await expect(page.getByTestId('staging-source-list')).toHaveCount(0)
    await expect(page.getByTestId('workspace').or(page.getByTestId('dual-log-view')).or(page.locator('.workspace'))).toBeVisible({
      timeout: 60_000,
    })
  })

  test('multi-log import → review → export dialog (no mapping bundle required)', async ({ page }) => {
    const { a, b } = ensureFixtures()
    await page.goto('/')
    const chooserPromise = page.waitForEvent('filechooser')
    await page.getByTestId('multi-source-dropzone').click()
    const chooser = await chooserPromise
    await chooser.setFiles([a, b])

    await expect(page.getByTestId('staging-source-list')).toBeVisible({ timeout: 30_000 })
    await page.getByRole('button', { name: cs.correlationStaging.confirm }).click()
    await expect(page.getByTestId('correlation-workspace')).toBeVisible({ timeout: 90_000 })

    await page.getByTestId('correlation-export-open').click()
    await expect(page.getByTestId('correlation-export-dialog')).toBeVisible()
    // Mapping bundle is a separate optional action — not required to open export dialog.
    await expect(page.getByTestId('correlation-export-dialog')).toContainText(/AI|export|soubor/i)
    await page.keyboard.press('Escape')
  })

  test('resolve-only entry is reachable from empty shell (lookup path)', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByTestId('empty-resolve-return-open')).toBeVisible()
    // Choosing a bundle file goes straight to the lookup screen — no intermediate step.
    await chooseMappingBundleFromLanding(page)
    await expect(page.getByTestId('mapping-resolve-workspace')).toBeVisible({ timeout: 15_000 })
    await expect(page.getByTestId('resolve-return-lookup')).toBeVisible()
  })
})
