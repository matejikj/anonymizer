import { test, expect } from '@playwright/test'
import { buildEthIpUdp, buildSipInviteWithSdp, buildRtpPayload, buildRtcpSdes, VOIP_SEED, envelope } from '../pcap/fixtures/voipCorpus'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import { classicHeader } from '../pcap/helpers/diagnosticPipeline'
import { loadUniversalFiles } from './helpers/loadFiles'
import { selectPcapLevel } from './helpers/selectPcapLevel'

for (const level of ['diagnostic', 'high-privacy'] as const) {
  test(`${level}: outcome reports observed SIP/SDP counts across real workers`, async ({ page }) => {
    const payloads = [new TextEncoder().encode('SIP/2.0 200 OK\r\nCall-ID: synthetic@example.test\r\nContent-Length: 0\r\n\r\n'), buildSipInviteWithSdp()]
    const packets = payloads.map((payload, i) => envelope(buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, payload), i))
    const buffer = Buffer.from(writeClassicPcap({ header: classicHeader(), packets }))
    await page.goto('/')
    await selectPcapLevel(page, level)
    await loadUniversalFiles(page, { name: 'synthetic-sip.pcap', mimeType: 'application/octet-stream', buffer })
    const panel = page.getByTestId('pcap-workspace-outcome')
    await expect(panel).toBeVisible({ timeout: 60_000 })
    await expect(panel.locator('.anonymization-outcome__family')).toHaveCount(3)
    for (const family of ['sip', 'sdp', 'network-headers']) {
      const row = page.getByTestId(`pcap-workspace-outcome-family-${family}`)
      await expect(row).toHaveAttribute('data-family-state', 'anonymized')
      await expect(page.getByTestId(`pcap-workspace-outcome-count-${family}`)).toHaveText(family === 'sdp' ? '1 paket' : '2 pakety')
    }
    await expect(page.getByTestId('pcap-workspace-outcome-summary')).not.toContainText(/VPN|DHCP|DMR|DNS|HTTP/)
    await expect(page.getByTestId('pcap-workspace-outcome-impact')).toContainText('analyzovatelné rodiny: 3')
    for (const [i, family] of ['sdp', 'sip', 'network-headers'].entries()) {
      if (i > 0) await page.getByTestId('pcap-outcome-dialog-open').click()
      await page.getByTestId(`pcap-workspace-outcome-show-${family}`).click()
      await expect(panel).not.toBeVisible()
      for (const view of ['original', 'anonymized']) {
        const grid = page.getByTestId(`pcap-packet-grid-${view}`)
        await expect(grid).toHaveAttribute('aria-rowcount', family === 'sdp' ? '1' : '2')
        await expect(grid.locator('[data-packet-index="1"]')).toBeVisible()
        if (family === 'sdp') await expect(grid.locator('[data-packet-index="0"]')).toHaveCount(0)
        await expect(page.locator(`[data-testid="pcap-packet-details"][data-data-view="${view}"] h3`)).toContainText('1')
      }
    }
    await page.getByTestId('pcap-filter-clear').click()
    await expect(page.getByTestId('pcap-packet-grid-original')).toHaveAttribute('aria-rowcount', '2')
  })
}

for (const level of ['diagnostic', 'high-privacy'] as const) {
  test(`${level}: show media family selects both RTP and RTCP and the filter can be cleared`, async ({ page }) => {
    const src = VOIP_SEED.ip.split('.').map(Number)
    const packets = [
      envelope(buildEthIpUdp(src, [10, 0, 0, 2], 5060, 5060, buildSipInviteWithSdp()), 0),
      envelope(buildEthIpUdp(src, [10, 0, 0, 2], VOIP_SEED.mediaPort, 40000, buildRtpPayload()), 1),
      envelope(buildEthIpUdp(src, [10, 0, 0, 2], VOIP_SEED.mediaPort + 1, 40001, buildRtcpSdes()), 2),
    ]
    await page.goto('/')
    await selectPcapLevel(page, level)
    await loadUniversalFiles(page, { name: 'synthetic-media.pcap', mimeType: 'application/octet-stream',
      buffer: Buffer.from(writeClassicPcap({ header: classicHeader(), packets })) })
    await expect(page.getByTestId('pcap-workspace-outcome')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('pcap-workspace-outcome-count-rtp-rtcp')).toHaveText('2 pakety')
    await page.getByTestId('pcap-workspace-outcome-show-rtp-rtcp').click()
    await expect(page.getByTestId('pcap-display-filter-input')).toHaveValue('protocol.family == "rtp-rtcp"')
    for (const view of ['original', 'anonymized']) {
      const grid = page.getByTestId(`pcap-packet-grid-${view}`)
      // High privacy intentionally drops media from the exported/anonymized pane.
      const dropped = level === 'high-privacy' && view === 'anonymized'
      await expect(grid).toHaveAttribute('aria-rowcount', dropped ? '0' : '2')
      await expect(grid.locator('[data-packet-index="0"]')).toHaveCount(0)
      if (!dropped) {
        await expect(grid.locator('[data-packet-index="1"]')).toBeVisible()
        await expect(grid.locator('[data-packet-index="2"]')).toBeVisible()
      }
    }
    for (const [expression, count] of [['rtcp', '1'], ['udp', '3'], ['ipv4', '3']]) {
      await page.getByTestId('pcap-display-filter-input').fill(expression!)
      await page.getByTestId('pcap-filter-apply').click()
      for (const view of ['original', 'anonymized']) {
        const expected = level === 'high-privacy' && view === 'anonymized' ? (expression === 'rtcp' ? '0' : '1') : count!
        await expect(page.getByTestId(`pcap-packet-grid-${view}`)).toHaveAttribute('aria-rowcount', expected)
      }
    }
    await page.getByTestId('pcap-filter-clear').click()
    await expect(page.getByTestId('pcap-packet-grid-original')).toHaveAttribute('aria-rowcount', '3')
  })
}

test('show other family includes an opaque UDP payload', async ({ page }) => {
  const packets = [
    envelope(buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, buildSipInviteWithSdp()), 0),
    envelope(buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 65000, 65001,
      new TextEncoder().encode('opaque-synthetic-payload-12345678')), 1),
  ]
  await page.goto('/')
  await selectPcapLevel(page, 'diagnostic')
  await loadUniversalFiles(page, { name: 'synthetic-opaque.pcap', mimeType: 'application/octet-stream',
    buffer: Buffer.from(writeClassicPcap({ header: classicHeader(), packets })) })
  await expect(page.getByTestId('pcap-workspace-outcome')).toBeVisible({ timeout: 60_000 })
  await expect(page.getByTestId('pcap-workspace-outcome-count-other')).toHaveText('1 paket')
  await page.getByTestId('pcap-workspace-outcome-show-other').click()
  for (const view of ['original', 'anonymized']) {
    const grid = page.getByTestId(`pcap-packet-grid-${view}`)
    await expect(grid).toHaveAttribute('aria-rowcount', '1')
    await expect(grid.locator('[data-packet-index="1"]')).toBeVisible()
    await expect(grid.locator('[data-packet-index="0"]')).toHaveCount(0)
    await expect(page.locator(`[data-testid="pcap-packet-details"][data-data-view="${view}"] h3`)).toContainText('1')
  }
})
