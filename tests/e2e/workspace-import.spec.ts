import { closeTextOutcomeDialog } from './helpers/textOutcome.ts'
import { test, expect } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
// Real template logs live in the gitignored logs/ dir; fixture tests skip when absent.
const fixtureLogsDir = path.resolve(here, '../../logs')

const FIXTURES = [
  'template-edge.log',
  'template-appsrv.log',
  'template-app-modules.log',
  'template-rgw-server.log',
  'sample_ops_20261022.log',
] as const

test.describe('Text import and dual panes', () => {
  test('sample log shows original and anonymized side by side', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    await expect(page.getByTestId('dual-log')).toBeVisible()
    await expect(page.getByTestId('pane-original')).toBeVisible()
    await expect(page.getByTestId('pane-anonymized')).toBeVisible()

    const originalText = await page.locator('[data-pane="original"]').innerText()
    const anonText = await page.locator('[data-pane="anonymized"]').innerText()
    expect(originalText.length).toBeGreaterThan(50)
    expect(anonText.length).toBeGreaterThan(50)
    // Sensitive sample tokens must not appear in anonymized pane DOM text
    expect(anonText).not.toContain('10.16.1.105')
    expect(anonText).not.toContain('Krejci Iveta')
    expect(anonText).not.toContain('disp4')
    expect(anonText).toMatch(/10\.255\.|account-|Person |host-/)
  })

  for (const name of FIXTURES) {
    test(`loads fixture ${name}`, async ({ page }) => {
      const filePath = path.join(fixtureLogsDir, name)
      test.skip(!fs.existsSync(filePath), `${name} not present in logs/`)
      await page.goto('/')
      await page.getByTestId('file-input').setInputFiles(filePath)
      await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 120_000 })
      await closeTextOutcomeDialog(page)
      await expect(page.getByTestId('pane-original')).toBeVisible()
      await expect(page.getByTestId('pane-anonymized')).toBeVisible()
      await expect(page.getByTestId('session-file-name')).toContainText(name)

      const originalText = await page.locator('[data-pane="original"]').innerText()
      const anonText = await page.locator('[data-pane="anonymized"]').innerText()
      expect(originalText.length).toBeGreaterThan(200)
      expect(anonText.length).toBeGreaterThan(200)
      // Spot-check: common fixture IP / disp must not leak when present in original
      if (originalText.includes('disp5')) {
        expect(anonText).not.toContain('disp5')
      }
      if (originalText.includes('10.16.1.105')) {
        expect(anonText).not.toContain('10.16.1.105')
      }
    })
  }

  test('close log returns to empty state', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    await expect(page.getByTestId('close-log')).toBeVisible()
    await expect(page.getByTestId('export-download')).toBeVisible()
    await expect(page.getByTestId('mapping-bundle-export-open')).toBeVisible()
    await expect(page.getByTestId('new-log')).toHaveCount(0)
    await expect(page.getByTestId('workspace-more')).toHaveCount(0)
    await expect(page.getByTestId('resolve-open-toggle')).toHaveCount(0)
    await expect(page.getByTestId('mapping-bundle-import-open')).toHaveCount(0)
    await expect(page.getByTestId('session-stepper')).toBeVisible()
    await expect(page.getByTestId('session-step-review')).toHaveAttribute('aria-current', 'step')
    await page.getByTestId('close-log').click()
    await expect(page.getByTestId('landing')).toBeVisible()
  })

  test('cancel during file import returns to empty', async ({ page }) => {
    const filePath = path.join(fixtureLogsDir, 'template-rgw-server.log')
    test.skip(!fs.existsSync(filePath), 'template-rgw-server.log not present in logs/')
    await page.goto('/')
    await page.getByTestId('file-input').setInputFiles(filePath)
    const cancel = page.getByTestId('cancel-analysis')
    // Race: either cancel while importing, or finish then close the log.
    try {
      await cancel.click({ timeout: 3_000 })
    } catch {
      await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
      await closeTextOutcomeDialog(page)
      await page.getByTestId('close-log').click()
    }
    await expect(page.getByTestId('landing')).toBeVisible({
      timeout: 15_000,
    })
  })
})
