import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

for (const theme of ['light', 'dark'] as const) {
  for (const width of [1440, 390]) {
    test(`documentation and help are readable: ${theme}, ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 950 })
      await page.addInitScript((value) => {
        localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify(value))
        localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', 'true')
      }, theme)
      await page.goto('/')
      const docsButton = page.getByTestId('docs-open')
      await expect(docsButton).toHaveText('Technická dokumentace')
      await expect(page.getByTestId('help-open')).toHaveText('Nápověda')
      await expect(docsButton.locator('span')).toBeVisible()
      await expect(page.getByTestId('help-open').locator('span')).toBeVisible()
      await expect.poll(() => page.getByTestId('app-header').evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true)
      await expect.poll(() => page.getByTestId('app-header').evaluate(el => {
        const header = el.getBoundingClientRect()
        return Array.from(el.querySelectorAll('button, select')).every(control => {
          const rect = control.getBoundingClientRect()
          return rect.top >= header.top && rect.bottom <= header.bottom && rect.right <= header.right
        })
      })).toBe(true)
      await page.screenshot({ path: `/tmp/anonym-header-${theme}-${width}.png` })
      await docsButton.click()
      const docs = page.getByTestId('docs-panel')
      await expect(docs.getByRole('heading', { name: 'Technická dokumentace', exact: true })).toBeFocused()
      await expect(docs.locator('details')).toHaveCount(10)
      await expect(docs.locator('details[open]')).toHaveCount(1)
      await expect(docs.locator('details[open]')).toContainText('Vysoké soukromí')
      await page.screenshot({ path: `/tmp/anonym-docs-overview-${theme}-${width}.png` })
      // Every collapsed section remains reachable inside the modal's focus trap.
      await docs.locator('summary').first().focus()
      await page.keyboard.press('Tab')
      await expect(docs.locator('summary').nth(1)).toBeFocused()
      for (let index = 2; index < 10; index++) {
        await page.keyboard.press('Tab')
        await expect(docs.locator('summary').nth(index)).toBeFocused()
      }
      await page.keyboard.press('Enter')
      await expect(docs.locator('details').last()).toContainText('Je nešifrovaný a bez hesla')
      const applicationChapter = docs.locator('details').filter({ hasText: 'Stejný princip použijeme na ostatní aplikační protokoly' })
      await applicationChapter.locator('summary').click()
      await expect(applicationChapter.getByRole('heading', { name: 'Web, přihlašování a šifrované přenosy' })).toBeVisible()
      await expect(applicationChapter).toContainText('SNI')
      await expect(docs.getByRole('table')).toHaveCount(0)
      await expect(docs.getByRole('searchbox')).toHaveCount(0)
      // Long protocol names and code references must wrap inside the modal.
      await expect.poll(() => docs.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true)
      const violations = await new AxeBuilder({ page }).include('[data-testid="docs-panel"]')
        .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()
      expect(violations.violations.filter(v => v.impact === 'critical' || v.impact === 'serious')).toEqual([])
      await page.screenshot({ path: `/tmp/anonym-docs-${theme}-${width}.png` })
      await page.keyboard.press('Escape')
      await expect(docsButton).toBeFocused()
      await page.getByTestId('help-open').click()
      await page.getByTestId('help-tab-text').click()
      await expect(page.getByTestId('help-panel-body')).toContainText('„Smazat“ vedle „Nový“')
      await page.getByTestId('help-tab-pcap').click()
      await expect(page.getByTestId('help-panel-body')).toContainText('Pozice 34 B · délka 803 B')
      await expect(page.getByTestId('help-panel-body')).toContainText('synchronizuje')
      await page.keyboard.press('Escape')
      await expect(page.getByTestId('help-open')).toBeFocused()
    })
  }
}
