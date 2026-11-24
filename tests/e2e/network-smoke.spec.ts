import { closeTextOutcomeDialog } from './helpers/textOutcome.ts'
import { test, expect } from '@playwright/test'
import { cs } from '../../src/i18n/cs'

/**
 * After the document and its static assets load, no further HTTP(S) requests
 * may leave the origin (ARCHITECTURE §12.1 / §15.3).
 */
test('network smoke: no runtime requests after static assets', async ({ page }) => {
  const runtimeRequests: string[] = []
  let collecting = false

  page.on('request', (request) => {
    if (!collecting) return
    const url = request.url()
    const isHttp = url.startsWith('http://') || url.startsWith('https://')
    if (!isHttp) return
    const origin = new URL(page.url()).origin
    if (!url.startsWith(origin)) {
      runtimeRequests.push(url)
      return
    }
    runtimeRequests.push(url)
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: cs.empty.landingLead })).toBeVisible()
  collecting = true
  await page.waitForTimeout(1500)
  await page.getByTestId('multi-source-dropzone').focus()
  await page.getByTestId('paste-toggle').click()
  await page.getByLabel(cs.empty.textareaLabel).fill('demo line without leaving the browser')
  await page.waitForTimeout(500)

  expect(runtimeRequests, `Unexpected runtime requests: ${runtimeRequests.join(', ')}`).toEqual([])
})

test('network smoke: sample import + export never leaves the origin', async ({ page }) => {
  await page.goto('/')
  const origin = new URL(page.url()).origin
  const crossOrigin: string[] = []
  page.on('request', (request) => {
    const url = request.url()
    if (!url.startsWith('http://') && !url.startsWith('https://')) return
    if (!url.startsWith(origin)) crossOrigin.push(url)
  })

  await page.getByTestId('try-sample').click()
  await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
  await closeTextOutcomeDialog(page)
  await expect(page.getByTestId('export-bar')).toBeVisible()

  const downloadPromise = page.waitForEvent('download')
  await page.getByTestId('export-download').click()
  await downloadPromise
  await page.waitForTimeout(500)

  expect(crossOrigin, `Cross-origin requests: ${crossOrigin.join(', ')}`).toEqual([])
})

test('entry URL opens anonymizer directly without auth chrome', async ({ page, context }) => {
  const response = await page.goto('/')
  expect(response?.ok()).toBeTruthy()
  await expect(page.getByRole('heading', { name: cs.empty.landingLead })).toBeVisible()
  await expect(page.getByTestId('app-privacy-badge')).toBeVisible()
  await expect(page.getByText(/login|sign in|přihlášení|oauth|sso/i)).toHaveCount(0)

  const cookies = await context.cookies()
  const authCookies = cookies.filter((c) => /session|auth|token|sid/i.test(c.name))
  expect(authCookies).toEqual([])
})
