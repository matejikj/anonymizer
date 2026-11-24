import { closeTextOutcomeDialog } from '../../e2e/helpers/textOutcome.ts'
import { test, expect } from '@playwright/test'
import path from 'node:path'
import fs from 'node:fs'
import os from 'node:os'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const resultsDir = path.resolve(here, '../results')

/**
 * Product UI wiring for a representative multi-MB log.
 * Absolute §11.2 30/90MB detect wall-clock is recorded in `npm run bench:text-pipeline`.
 */
test.describe('Krok 10 — product UI performance smoke', () => {
  test('multi-MB file reaches workspace and exports', async ({ page }, testInfo) => {
    test.setTimeout(5 * 60_000)
    const lines: string[] = []
    for (let i = 0; i < 20_000; i++) {
      lines.push(
        `2026-08-16T12:00:00.${String(i % 1000).padStart(3, '0')} peer=10.${i % 200}.${i % 50}.${i % 250} user=disp${(i % 24) + 1} host=node-${i % 40}.local`,
      )
    }
    const text = lines.join('\n') + '\n'
    const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'rnd-log-anonymizer-ui-'))
    const filePath = path.join(dir, 'ui-smoke.log')
    await fs.promises.writeFile(filePath, text, 'utf8')
    const utf8Mb = Buffer.byteLength(text, 'utf8') / (1024 * 1024)

    await page.goto('/')
    const t0 = Date.now()
    await page.getByTestId('file-input').setInputFiles(filePath)
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 120_000 })
    await closeTextOutcomeDialog(page)
    await expect(page.getByTestId('export-bar')).toBeVisible()
    const workspaceMs = Date.now() - t0

    const downloadPromise = page.waitForEvent('download')
    const expT0 = Date.now()
    await page.getByTestId('export-download').click()
    const download = await downloadPromise
    const exportMs = Date.now() - expT0
    expect(download.suggestedFilename()).toBe('ui-smoke.anonymized.log')

    const row = {
      browser: testInfo.project.name,
      kind: 'ui-smoke-20k',
      utf8Mb,
      workspaceMs,
      exportMs,
    }
    fs.mkdirSync(resultsDir, { recursive: true })
    fs.writeFileSync(
      path.join(resultsDir, `product-ui-${testInfo.project.name}-smoke.json`),
      JSON.stringify(row, null, 2),
    )
    // Wiring gate: must complete; absolute §11.3 times for full profiles are in bench:text-pipeline / Krok 0.
    expect(workspaceMs).toBeLessThan(60_000)
    expect(exportMs).toBeLessThan(5_000)
  })
})
