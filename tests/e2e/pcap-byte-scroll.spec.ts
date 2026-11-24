import { test, expect, type Locator } from '@playwright/test'
import { buildEthIpUdp, envelope } from '../pcap/fixtures/voipCorpus'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import { classicHeader } from '../pcap/helpers/diagnosticPipeline'
import { loadUniversalFiles } from './helpers/loadFiles'
import { selectPcapLevel } from './helpers/selectPcapLevel'

async function expectViewportCovered(grid: Locator, bytes: Uint8Array | null) {
  await expect.poll(() => grid.evaluate((el, original) => {
    const view = el.getBoundingClientRect()
    const rows = [...el.querySelectorAll('.pcap-byte-grid__row')]
    const first = rows[0]?.getBoundingClientRect()
    const last = rows.at(-1)?.getBoundingClientRect()
    const spacer = el.firstElementChild!.getBoundingClientRect()
    const style = getComputedStyle(el)
    const top = view.top + el.clientTop + Number.parseFloat(style.paddingTop)
    const bottom = Math.min(view.top + el.clientTop + el.clientHeight - Number.parseFloat(style.paddingBottom), spacer.bottom)
    if (!first || !last || first.top > top + 1 || last.bottom < bottom - 1) return false
    const offsets = [...el.querySelectorAll<HTMLElement>('.pcap-byte-grid__byte')]
    const ascii = [...el.querySelectorAll<HTMLElement>('.pcap-byte-grid__ascii-char')]
    if (ascii.length !== offsets.length) return false
    return offsets.every((cell, i) => {
      const offset = Number(cell.dataset.byteOffset)
      const byte = Number.parseInt(cell.textContent!, 16)
      return ascii[i]!.dataset.byteOffset === cell.dataset.byteOffset
        && ascii[i]!.textContent === (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')
        && (i === 0 || offset === Number(offsets[i - 1]!.dataset.byteOffset) + 1)
        && (!original || cell.textContent === original[offset]!.toString(16).padStart(2, '0'))
    })
  }, bytes ? [...bytes] : null)).toBe(true)
}

test('byte viewport stays filled while scrolling, resizing and switching packet sizes', async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 1400 })
  await page.addInitScript(() => localStorage.setItem('rnd-log-anonymizer:pref:pcapWiresharkUi', JSON.stringify({
    listPanelRatio: 0.2, detailsPanelRatio: 0.2,
  })))
  const frames = [884, 65001].map(length => buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 65000, 65001,
    Uint8Array.from({ length: length - 42 }, (_, i) => 32 + i % 95)))
  await page.goto('/')
  await selectPcapLevel(page, 'diagnostic')
  await loadUniversalFiles(page, { name: 'byte-scroll.pcap', mimeType: 'application/octet-stream',
    buffer: Buffer.from(writeClassicPcap({ header: classicHeader(), packets: frames.map(envelope) })) })
  await expect(page.getByTestId('pcap-workspace-outcome')).toBeVisible({ timeout: 60_000 })
  await page.getByTestId('pcap-outcome-dialog-close').click()
  for (const packetIndex of [0, 1, 0]) {
    await page.getByTestId('pcap-packet-grid-original').locator(`[data-packet-index="${packetIndex}"]`).click()
    for (const view of ['original', 'anonymized']) {
      const grid = page.locator(`[data-testid="pcap-byte-grid"][data-data-view="${view}"] .pcap-byte-grid`)
      await expect(grid).toBeVisible()
      await expect(page.locator(`[data-testid="pcap-byte-grid"][data-data-view="${view}"] .pcap-byte-grid__meta-len`)).toHaveText(`${frames[packetIndex]!.length} B`)
      for (const fraction of [0, 0.25, 0.65, 1, 0.4, 0]) {
        await grid.evaluate((el, f) => { el.scrollTop = (el.scrollHeight - el.clientHeight) * f }, fraction)
        await expectViewportCovered(grid, view === 'original' ? frames[packetIndex]! : null)
        expect(await grid.locator('.pcap-byte-grid__row').count()).toBeLessThan(120)
        if (fraction === 1) {
          await expect(grid.locator(`.pcap-byte-grid__byte[data-byte-offset="${frames[packetIndex]!.length - 1}"]`)).toBeVisible()
        }
      }
    }
  }
  await page.setViewportSize({ width: 1600, height: 1000 })
  await page.setViewportSize({ width: 1600, height: 1600 })
  for (const view of ['original', 'anonymized']) {
    const grid = page.locator(`[data-testid="pcap-byte-grid"][data-data-view="${view}"] .pcap-byte-grid`)
    await grid.evaluate(el => { el.scrollTop = (el.scrollHeight - el.clientHeight) * 0.5 })
    await expectViewportCovered(grid, view === 'original' ? frames[0]! : null)
  }
})

test('ASCII spaces keep byte row heights uniform and scrolling stable', async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 1400 })
  await page.addInitScript(() => localStorage.setItem('rnd-log-anonymizer:pref:pcapWiresharkUi', JSON.stringify({
    listPanelRatio: 0.2, detailsPanelRatio: 0.2,
  })))
  const payload = new Uint8Array(718 - 42).fill(65)
  payload[6] = 32 // An ASCII-space first cell followed by text at frame offset 0x30.
  const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 65000, 65001, payload)
  await page.goto('/')
  await selectPcapLevel(page, 'diagnostic')
  await loadUniversalFiles(page, { name: 'byte-spaces.pcap', mimeType: 'application/octet-stream',
    buffer: Buffer.from(writeClassicPcap({ header: classicHeader(), packets: [envelope(frame, 0)] })) })
  await expect(page.getByTestId('pcap-workspace-outcome')).toBeVisible({ timeout: 60_000 })
  await page.getByTestId('pcap-outcome-dialog-close').click()
  for (const view of ['original', 'anonymized']) {
    const grid = page.locator(`[data-testid="pcap-byte-grid"][data-data-view="${view}"] .pcap-byte-grid`)
    await expect(grid.locator('.pcap-byte-grid__row').first()).toBeVisible()
    await expect.poll(() => grid.locator('.pcap-byte-grid__row').evaluateAll(rows => {
      const heights = rows.map(row => row.getBoundingClientRect().height)
      return Math.max(...heights) - Math.min(...heights)
    })).toBeLessThan(0.5)
    for (const top of [270, 500, 0, 270]) {
      await grid.evaluate((el, y) => { el.scrollTop = y }, top)
      await expectViewportCovered(grid, view === 'original' ? frame : null)
    }
  }
})
