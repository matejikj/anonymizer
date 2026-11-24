import { test, expect } from '@playwright/test'
import { cs } from '../../src/i18n/cs'

test.describe('keyboard-accessible shell', () => {
  test('shell controls are reachable without a pointer', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: cs.empty.landingLead })).toBeVisible()

    const skip = page.getByRole('link', { name: cs.skipToContent })
    await skip.focus()
    await expect(skip).toBeFocused()
    await page.keyboard.press('Enter')
    await expect(page.locator('#main')).toBeFocused()

    const dropzone = page.getByLabel(cs.a11y.dropzone)
    await dropzone.focus()
    await expect(dropzone).toBeFocused()
    await page.keyboard.press('Enter')
    await page.keyboard.press('Escape')
    await expect(page.getByRole('heading', { name: cs.empty.landingLead })).toBeVisible()
  })

  test('primary actions are keyboard focusable', async ({ page }) => {
    await page.goto('/')

    await page.getByTestId('multi-source-dropzone').focus()
    await expect(page.getByTestId('multi-source-dropzone')).toBeFocused()

    for (const name of [cs.empty.pasteToggle, cs.empty.trySample]) {
      const button = page.getByRole('button', { name })
      await button.focus()
      await expect(button).toBeFocused()
    }

    await page.getByTestId('paste-toggle').click()
    const textarea = page.getByLabel(cs.empty.textareaLabel)
    await textarea.focus()
    await expect(textarea).toBeFocused()
  })

  test('primary buttons have visible names for assistive tech', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByTestId('multi-source-dropzone')).toBeVisible()
    await expect(page.getByRole('button', { name: cs.empty.pasteToggle })).toBeVisible()
    await expect(page.getByRole('button', { name: cs.empty.trySample })).toBeVisible()
    await page.getByTestId('paste-toggle').click()
    await expect(page.getByLabel(cs.empty.textareaLabel)).toBeVisible()
    await expect(page.getByRole('button', { name: cs.empty.pasteClipboard })).toBeVisible()
  })
})
