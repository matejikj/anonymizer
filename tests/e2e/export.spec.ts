import { test, expect } from '@playwright/test'
import path from 'node:path'
import fs from 'node:fs/promises'
import os from 'node:os'

test.describe('Anonymized log export', () => {
  test('sample download uses rnd-log-anonymizer-anonymized-*.log and strips IPs', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('export-bar')).toBeVisible()

    const downloadPromise = page.waitForEvent('download')
    await page.getByTestId('export-download').click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toMatch(/^rnd-log-anonymizer-anonymized-\d{8}-\d{6}\.log$/)
    const filePath = await download.path()
    expect(filePath).toBeTruthy()
    const body = await fs.readFile(filePath!, 'utf8')
    expect(body).not.toContain('10.16.1.105')
    expect(body).toContain('10.255.90.')
  })

  test('named .log download becomes *.anonymized.log', async ({ page }) => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'rnd-log-anonymizer-export-'))
    const src = path.join(tmp, 'app-server.log')
    await fs.writeFile(src, 'peer 10.16.1.105 ready\nuser=disp5\n', 'utf8')

    await page.goto('/')
    await page.getByTestId('file-input').setInputFiles(src)
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })

    const downloadPromise = page.waitForEvent('download')
    await page.getByTestId('export-download').click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toBe('app-server.anonymized.log')
    const out = await download.path()
    const body = await fs.readFile(out!, 'utf8')
    expect(body).not.toContain('10.16.1.105')
  })

  test('copy writes anonymized text to clipboard', async ({ page, browserName, context }) => {
    test.skip(browserName !== 'chromium', 'clipboard-read permission is Chromium-only in Playwright')
    await context.grantPermissions(['clipboard-read', 'clipboard-write'])
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('export-copy')).toBeVisible({ timeout: 60_000 })
    // AppShell Ctrl/Cmd+Shift+C clicks this same control (OS-level shortcut opens DevTools).
    await page.getByTestId('export-copy').click()
    await expect(page.getByTestId('app-toast')).toContainText('Zkopírováno', {
      timeout: 15_000,
    })
    const text = await page.evaluate(() => navigator.clipboard.readText())
    expect(text).not.toContain('10.16.1.105')
    expect(text.length).toBeGreaterThan(100)
  })

  test('exposed entity requires confirmation before export', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await page.getByTestId('review-tab-entities').click()
    const firstSwitch = page.locator('[data-testid^="entity-switch-"]').first()
    await firstSwitch.click()
    await expect(page.getByTestId('security-bar')).toHaveAttribute('data-level', 'exposed')

    await page.getByTestId('export-download').click()
    await expect(page.getByTestId('exposed-export-dialog')).toBeVisible()
    await expect(page.getByTestId('exposed-export-confirm')).toContainText(
      'Exportovat i s odkrytými hodnotami',
    )
    const downloadPromise = page.waitForEvent('download')
    await page.getByTestId('exposed-export-confirm').click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toMatch(/\.log$/)
  })

  test('export buttons disabled when analysis is blocked', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('export-bar')).toBeVisible({ timeout: 60_000 })
    await page.waitForFunction(
      () => typeof window.__RND_LOG_ANONYMIZER_E2E__?.markExportBlocked === 'function',
    )
    await expect
      .poll(async () => page.evaluate(() => window.__RND_LOG_ANONYMIZER_E2E__!.markExportBlocked()), {
        timeout: 10_000,
      })
      .toBe(true)
    await expect(page.getByTestId('security-bar')).toHaveAttribute('data-level', 'blocked')
    await expect(page.getByTestId('export-copy')).toBeDisabled()
    await expect(page.getByTestId('export-download')).toBeDisabled()
  })
})
