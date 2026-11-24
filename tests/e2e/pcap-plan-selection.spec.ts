import { test, expect } from '@playwright/test'
import { buildEthIpUdp, envelope } from '../pcap/fixtures/voipCorpus'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import { classicHeader } from '../pcap/helpers/diagnosticPipeline'
import { loadUniversalFiles } from './helpers/loadFiles'
import { selectPcapLevel } from './helpers/selectPcapLevel'

function capture(count: number) {
  const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 65000, 65001, new Uint8Array(32))
  return Buffer.from(writeClassicPcap({ header: classicHeader(), packets: Array.from({ length: count }, (_, i) => envelope(frame, i)) }))
}

test('packet details survive capture replacement with fewer, zero and more packets', async ({ page }) => {
  await page.setViewportSize({ width: 1700, height: 1000 })
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('/')
  await selectPcapLevel(page, 'diagnostic')
  for (const [step, count] of [8, 1, 0, 12].entries()) {
    const file = { name: `selection-${count}.pcap`, mimeType: 'application/octet-stream', buffer: capture(count) }
    if (step === 0) await loadUniversalFiles(page, file)
    else {
      await page.getByTestId('pcap-workspace-file-input').setInputFiles(file)
      await expect(page.getByTestId('pcap-replace-dialog')).toBeVisible()
      if (step === 1) {
        await page.getByTestId('pcap-replace-cancel').click()
        await expect(page.getByTestId('pcap-packet-details').first()).toContainText('Paket 7')
        await page.getByTestId('pcap-workspace-file-input').setInputFiles(file)
        await expect(page.getByTestId('pcap-replace-dialog')).toBeVisible()
      }
      await page.getByTestId('pcap-replace-confirm').click()
    }
    await expect(page.getByTestId('pcap-outcome-dialog')).toBeVisible({ timeout: 60_000 })
    await page.getByTestId('pcap-outcome-dialog-close').click()
    await expect(page.getByTestId('pcap-workspace')).toContainText(file.name)
    expect(errors).toEqual([])
    if (count === 0) {
      await expect(page.getByTestId('pcap-packet-details').first()).toContainText('Vyberte paket')
      continue
    }
    // History belongs to this capture. Returning to a packet from the previous,
    // longer capture used to restore an out-of-range index and crash the detail.
    await page.getByTestId('pcap-packet-grid-original').locator('[data-packet-index="0"]').click()
    if (step > 0) {
      await page.keyboard.press('Alt+ArrowLeft')
      await expect(page.getByTestId('pcap-packet-details').first()).toContainText('Paket 0')
      expect(errors).toEqual([])
    }
    const index = count - 1
    await page.getByTestId('pcap-packet-grid-original').locator(`[data-packet-index="${index}"]`).click()
    for (const view of ['original', 'anonymized']) {
      const pane = page.getByTestId(`pcap-data-pane-${view}`)
      await expect(pane.getByTestId('pcap-packet-details')).toContainText(`Paket ${index}`)
      await expect(pane.locator('.pcap-byte-grid__meta-len')).toHaveText('74 B')
    }
    expect(errors).toEqual([])
  }
})
