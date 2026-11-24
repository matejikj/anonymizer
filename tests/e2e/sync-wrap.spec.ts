import { closeTextOutcomeDialog } from './helpers/textOutcome.ts'
import { test, expect } from '@playwright/test'

/**
 * Sync / wrap / navigation (ARCHITECTURE §4.4).
 */
test.describe('Sync wrap navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    await expect(page.getByTestId('dual-log')).toBeVisible()
  })

  test('first middle last line stay aligned without wrap', async ({ page }) => {
    await expect(page.getByTestId('wrap-toggle')).not.toBeChecked()

    const result = await page.evaluate(async () => {
      const left = document.querySelector('[data-pane="original"]')?.closest('.cm-editor')
      const right = document.querySelector('[data-pane="anonymized"]')?.closest('.cm-editor')
      if (!left || !right) return null
      const leftScroll = left.querySelector('.cm-scroller') as HTMLElement
      const rightScroll = right.querySelector('.cm-scroller') as HTMLElement

      const measure = () => ({
        leftTop: leftScroll.scrollTop,
        rightTop: rightScroll.scrollTop,
      })

      const positions: Array<ReturnType<typeof measure> & { label: string }> = []

      leftScroll.scrollTop = 0
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
      positions.push({ label: 'first', ...measure() })

      leftScroll.scrollTop = Math.floor((leftScroll.scrollHeight - leftScroll.clientHeight) / 2)
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
      positions.push({ label: 'middle', ...measure() })

      leftScroll.scrollTop = leftScroll.scrollHeight
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
      positions.push({ label: 'last', ...measure() })

      return positions
    })

    expect(result).not.toBeNull()
    for (const p of result!) {
      expect(Math.abs(p.leftTop - p.rightTop), p.label).toBeLessThan(40)
    }
  })

  test('wrap toggle keeps both panes wrapping, re-anchors, and persists', async ({ page }) => {
    const topBefore = await page.evaluate(() => {
      const left = document.querySelector('[data-pane="original"]')?.closest('.cm-editor')
      const scroller = left?.querySelector('.cm-scroller') as HTMLElement | null
      if (!scroller) return -1
      scroller.scrollTop = Math.min(200, scroller.scrollHeight / 3)
      return scroller.scrollTop
    })
    expect(topBefore).toBeGreaterThanOrEqual(0)

    await page.getByTestId('wrap-toggle').check()
    await expect(page.getByTestId('wrap-toggle')).toBeChecked()

    // Preference persisted across reload
    await page.reload()
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    await expect(page.getByTestId('wrap-toggle')).toBeChecked()

    // Wrap + unequal pane widths still keep top lines close
    const splitter = page.getByTestId('pane-splitter')
    const box = await splitter.boundingBox()
    expect(box).toBeTruthy()
    await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2)
    await page.mouse.down()
    await page.mouse.move(box!.x - 120, box!.y + box!.height / 2)
    await page.mouse.up()

    const aligned = await page.evaluate(async () => {
      const left = document.querySelector('[data-pane="original"]')?.closest('.cm-editor')
      const right = document.querySelector('[data-pane="anonymized"]')?.closest('.cm-editor')
      if (!left || !right) return 999
      const leftScroll = left.querySelector('.cm-scroller') as HTMLElement
      const rightScroll = right.querySelector('.cm-scroller') as HTMLElement
      leftScroll.scrollTop = Math.floor((leftScroll.scrollHeight - leftScroll.clientHeight) / 2)
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
      return Math.abs(leftScroll.scrollTop - rightScroll.scrollTop)
    })
    expect(aligned).toBeLessThan(80)

    await page.getByTestId('wrap-toggle').uncheck()
  })

  test('occurrence next/prev jumps and highlights both panes', async ({ page }) => {
    await expect(page.getByTestId('occ-next')).toBeEnabled({ timeout: 15_000 })
    await page.getByTestId('occ-next').click()
    await expect(page.getByTestId('occ-counter')).not.toHaveText('—')
    const counter1 = await page.getByTestId('occ-counter').textContent()
    expect(counter1).toMatch(/1\s*\/\s*\d+/)

    const lineAfterFirst = await page.getByTestId('focused-line').textContent()

    await page.getByTestId('occ-next').click()
    const counter2 = await page.getByTestId('occ-counter').textContent()
    expect(counter2).not.toBe(counter1)

    // Jump while viewing — panes stay on the focused occurrence line
    await page.getByTestId('occ-prev').click()
    await expect(page.getByTestId('occ-counter')).toHaveText(counter1!)
    await expect(page.getByTestId('focused-line')).toHaveText(lineAfterFirst!)

    const highlights = await page.locator('.cm-sync-match').count()
    expect(highlights).toBeGreaterThanOrEqual(1)
  })

  test('splitter can resize panes and persists ratio', async ({ page }) => {
    const splitter = page.getByTestId('pane-splitter')
    const box = await splitter.boundingBox()
    expect(box).toBeTruthy()
    await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2)
    await page.mouse.down()
    await page.mouse.move(box!.x + 80, box!.y + box!.height / 2)
    await page.mouse.up()

    const ratio = await page.evaluate(() => {
      const root = document.querySelector('[data-testid="dual-log"]') as HTMLElement | null
      return root?.style.getPropertyValue('--split-left') ?? ''
    })
    expect(ratio.length).toBeGreaterThan(0)

    await page.reload()
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    await expect(page.getByTestId('dual-log')).toBeVisible()
    const ratio2 = await page.evaluate(() => {
      const root = document.querySelector('[data-testid="dual-log"]') as HTMLElement | null
      if (!root) return ''
      return getComputedStyle(root).getPropertyValue('--split-left').trim()
    })
    expect(ratio2).toBeTruthy()
  })

  test('fast scroll thumb does not permanently desync', async ({ page }) => {
    const desync = await page.evaluate(async () => {
      const left = document.querySelector('[data-pane="original"]')?.closest('.cm-editor')
      const right = document.querySelector('[data-pane="anonymized"]')?.closest('.cm-editor')
      if (!left || !right) return 999
      const leftScroll = left.querySelector('.cm-scroller') as HTMLElement
      const rightScroll = right.querySelector('.cm-scroller') as HTMLElement
      const max = leftScroll.scrollHeight - leftScroll.clientHeight
      for (let i = 0; i < 20; i++) {
        leftScroll.scrollTop = (max * i) / 19
        await new Promise((r) => requestAnimationFrame(r))
      }
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
      return Math.abs(leftScroll.scrollTop - rightScroll.scrollTop)
    })
    expect(desync).toBeLessThan(60)
  })

  test('last line with and without trailing newline stays reachable', async ({ page }) => {
    // With trailing newline
    await page.goto('/')
    await page.getByTestId('file-input').setInputFiles({
      name: 'with-nl.log',
      mimeType: 'text/plain',
      buffer: Buffer.from('line1 10.1.1.1\nline2 10.1.1.2\nline3 end\n'),
    })
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    await expect(page.getByTestId('dual-log')).toBeVisible()
    const withNl = await page.evaluate(async () => {
      const left = document.querySelector('[data-pane="original"]')?.closest('.cm-editor')
      const right = document.querySelector('[data-pane="anonymized"]')?.closest('.cm-editor')
      if (!left || !right) return { ok: false, reason: 'missing' }
      const leftScroll = left.querySelector('.cm-scroller') as HTMLElement
      const rightScroll = right.querySelector('.cm-scroller') as HTMLElement
      leftScroll.scrollTop = leftScroll.scrollHeight
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
      return {
        ok: Math.abs(leftScroll.scrollTop - rightScroll.scrollTop) < 40,
        left: leftScroll.scrollTop,
        right: rightScroll.scrollTop,
      }
    })
    expect(withNl.ok, JSON.stringify(withNl)).toBe(true)

    await page.getByTestId('close-log').click()
    await expect(page.getByTestId('landing')).toBeVisible()

    // Without trailing newline
    await page.getByTestId('file-input').setInputFiles({
      name: 'no-nl.log',
      mimeType: 'text/plain',
      buffer: Buffer.from('line1 10.1.1.1\nline2 10.1.1.2\nline3 end'),
    })
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    await expect(page.getByTestId('dual-log')).toBeVisible()
    const noNl = await page.evaluate(async () => {
      const left = document.querySelector('[data-pane="original"]')?.closest('.cm-editor')
      const right = document.querySelector('[data-pane="anonymized"]')?.closest('.cm-editor')
      if (!left || !right) return { ok: false, reason: 'missing' }
      const leftScroll = left.querySelector('.cm-scroller') as HTMLElement
      const rightScroll = right.querySelector('.cm-scroller') as HTMLElement
      leftScroll.scrollTop = leftScroll.scrollHeight
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
      return {
        ok: Math.abs(leftScroll.scrollTop - rightScroll.scrollTop) < 40,
        left: leftScroll.scrollTop,
        right: rightScroll.scrollTop,
      }
    })
    expect(noNl.ok, JSON.stringify(noNl)).toBe(true)
  })
})

test.describe('Short and long replacement lines', () => {
  test('horizontal sync stays usable on lines with replacements', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await closeTextOutcomeDialog(page)
    await expect(page.getByTestId('occ-next')).toBeEnabled({ timeout: 15_000 })

    await page.getByTestId('occ-next').click()
    await expect(page.getByTestId('occ-counter')).toHaveText(/1\s*\/\s*\d+/)

    const horiz = await page.evaluate(async () => {
      const left = document.querySelector('[data-pane="original"]')?.closest('.cm-editor')
      const right = document.querySelector('[data-pane="anonymized"]')?.closest('.cm-editor')
      if (!left || !right) return null
      const leftScroll = left.querySelector('.cm-scroller') as HTMLElement
      const rightScroll = right.querySelector('.cm-scroller') as HTMLElement
      leftScroll.scrollLeft = 80
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
      return {
        left: leftScroll.scrollLeft,
        right: rightScroll.scrollLeft,
      }
    })
    expect(horiz).not.toBeNull()
    // Sync / occurrence focus may adjust scroll; assert usable sync rather than exact Left=80.
    expect(horiz!.left).toBeGreaterThan(0)
    expect(Math.abs(horiz!.left - horiz!.right)).toBeLessThan(48)
    expect(horiz!.right).toBeGreaterThanOrEqual(0)
  })
})
