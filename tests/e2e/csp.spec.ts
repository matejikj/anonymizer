import { test, expect } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'

test('production HTML embeds CSP and Czech shell', async ({ page }) => {
  const indexPath = path.resolve('dist/index.html')
  expect(fs.existsSync(indexPath)).toBe(true)
  const html = fs.readFileSync(indexPath, 'utf8')
  expect(html).toMatch(/Content-Security-Policy/i)
  expect(html).toMatch(/connect-src 'none'/)
  expect(html).toMatch(/lang="cs"/)
  expect(html).not.toMatch(/login|oauth|signin/i)

  await page.goto('/')
  await expect(page.locator('meta[http-equiv="Content-Security-Policy"]')).toHaveCount(1)
})
