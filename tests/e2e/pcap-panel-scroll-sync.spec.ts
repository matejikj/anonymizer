import { test, expect, type Locator } from '@playwright/test'
import { buildEthIpUdp, buildSipInviteWithSdp, envelope } from '../pcap/fixtures/voipCorpus'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import { classicHeader } from '../pcap/helpers/diagnosticPipeline'
import { loadUniversalFiles } from './helpers/loadFiles'
import { selectPcapLevel } from './helpers/selectPcapLevel'

async function scrollAndExpectLinked(source: Locator, target: Locator, fraction: number) {
  await source.evaluate((el, f) => { el.scrollTop = (el.scrollHeight - el.clientHeight) * f }, fraction)
  await expect.poll(async () => {
    const top = await source.evaluate(el => el.scrollTop)
    const other = await target.evaluate(el => ({ top: el.scrollTop, max: el.scrollHeight - el.clientHeight }))
    return Math.abs(other.top - Math.min(top, other.max))
  }).toBeLessThan(1)
}

test('bytes, tree and changes scroll together in both directions', async ({ page }) => {
  await page.setViewportSize({ width: 1700, height: 1000 })
  await page.addInitScript(() => localStorage.setItem('rnd-log-anonymizer:pref:pcapWiresharkUi', JSON.stringify({
    listPanelRatio: 0.2, detailsPanelRatio: 0.4,
  })))
  const sip = buildSipInviteWithSdp()
  const frames = [sip, sip.slice(0, 200)].map(payload => buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, payload))
  await page.goto('/')
  await selectPcapLevel(page, 'diagnostic')
  await loadUniversalFiles(page, { name: 'panel-sync.pcap', mimeType: 'application/octet-stream',
    buffer: Buffer.from(writeClassicPcap({ header: classicHeader(), packets: frames.map(envelope) })) })
  await expect(page.getByTestId('pcap-workspace-outcome')).toBeVisible({ timeout: 60_000 })
  await page.getByTestId('pcap-outcome-dialog-close').click()
  await page.getByTestId('pcap-packet-grid-original').locator('[data-packet-index="0"]').click()
  const left = page.getByTestId('pcap-data-pane-original')
  const right = page.getByTestId('pcap-data-pane-anonymized')
  const leftBytes = left.locator('.pcap-byte-grid')
  const rightBytes = right.locator('.pcap-byte-grid')
  await expect(leftBytes.locator('.pcap-byte-grid__row').first()).toBeVisible()
  await expect(rightBytes.locator('.pcap-byte-grid__row').first()).toBeVisible()
  for (const fraction of [0.6, 1, 0.2]) await scrollAndExpectLinked(leftBytes, rightBytes, fraction)
  for (const fraction of [0.8, 0, 0.4]) await scrollAndExpectLinked(rightBytes, leftBytes, fraction)

  await left.getByTestId('pcap-tree-expand-all').click()
  const leftTree = left.locator('.pcap-dissection-tree-wrap')
  const rightTree = right.locator('.pcap-dissection-tree-wrap')
  const rangeNode = leftTree.locator('[data-offset="34"]').first()
  await expect(rangeNode.locator('.pcap-tree__meta')).toContainText('Pozice 34 B · délka')
  await expect(rangeNode.locator('.pcap-tree__meta')).toHaveAttribute('title', /Pozice se počítá od 0/)
  const fieldLength = await rangeNode.getAttribute('data-length')
  await rangeNode.click()
  await expect(left.getByTestId('pcap-byte-selection')).toHaveText(`Pozice 34 B · délka ${fieldLength} B`)
  await expect.poll(() => leftTree.evaluate(el => el.scrollHeight - el.clientHeight)).toBeGreaterThan(50)
  await scrollAndExpectLinked(leftTree, rightTree, 0.7)
  await scrollAndExpectLinked(rightTree, leftTree, 0.2)

  await left.getByTestId('pcap-detail-tab-changes').click()
  await expect(right.getByTestId('pcap-detail-tab-changes')).toHaveAttribute('aria-selected', 'true')
  const leftChanges = left.locator('.pcap-details-panel__changes-scroll')
  const rightChanges = right.locator('.pcap-details-panel__changes-scroll')
  await expect.poll(() => leftChanges.evaluate(el => el.scrollHeight - el.clientHeight)).toBeGreaterThan(50)
  await scrollAndExpectLinked(leftChanges, rightChanges, 0.65)
  await scrollAndExpectLinked(rightChanges, leftChanges, 0.15)
  await page.setViewportSize({ width: 1000, height: 1000 })
  await expect(page.getByTestId('pcap-comparison-workspace')).toHaveAttribute('data-layout', 'single')
  await expect(page.getByTestId('pcap-detail-tab-changes')).toHaveAttribute('aria-selected', 'true')
  await page.setViewportSize({ width: 1700, height: 1000 })
  await expect(page.getByTestId('pcap-comparison-workspace')).toHaveAttribute('data-layout', 'dual')
  await expect(left.getByTestId('pcap-detail-tab-changes')).toHaveAttribute('aria-selected', 'true')
  await expect(right.getByTestId('pcap-detail-tab-changes')).toHaveAttribute('aria-selected', 'true')
  await right.getByTestId('pcap-detail-tab-tree').click()
  await expect(left.getByTestId('pcap-detail-tab-tree')).toHaveAttribute('aria-selected', 'true')

  // A shorter packet must start at the top, without an old queued scroll restoring it.
  await page.getByTestId('pcap-packet-grid-original').locator('[data-packet-index="1"]').click()
  await expect.poll(() => leftBytes.evaluate(el => el.scrollTop)).toBe(0)
  await expect.poll(() => rightBytes.evaluate(el => el.scrollTop)).toBe(0)
})
