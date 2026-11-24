import { test, expect } from '@playwright/test'
import { loadUniversalFiles } from './helpers/loadFiles.ts'

function makeMinimalPcapBuffer(): Buffer {
  const packetData = Buffer.from([0xde, 0xad, 0xbe, 0xef])
  const size = 24 + 16 + packetData.length
  const buf = Buffer.alloc(size)
  buf.writeUInt32LE(0xa1b2c3d4, 0)
  buf.writeUInt16LE(2, 4)
  buf.writeUInt16LE(4, 6)
  buf.writeUInt32LE(65535, 16)
  buf.writeUInt32LE(1, 20)
  buf.writeUInt32LE(1700000000, 24)
  buf.writeUInt32LE(0, 28)
  buf.writeUInt32LE(packetData.length, 32)
  buf.writeUInt32LE(packetData.length, 36)
  packetData.copy(buf, 40)
  return buf
}

test.describe('PCAP preflight', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
  })

  test('accepts capture with wrong extension when magic bytes match', async ({ page }) => {
    const buffer = makeMinimalPcapBuffer()
    await loadUniversalFiles(page, {
      name: 'not-really-a-log.txt',
      mimeType: 'text/plain',
      buffer,
    })
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 30_000 })
    await expect(page.getByTestId('pcap-workspace')).toContainText('not-really-a-log.txt')
  })

  test('rejects unknown file without creating a session', async ({ page }) => {
    await loadUniversalFiles(page, {
      name: 'garbage.bin',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
    })
    await expect(page.getByTestId('empty-error')).toBeVisible()
    await expect(page.getByTestId('pcap-workspace')).toHaveCount(0)
  })

  test('replace dialog appears when opening another capture in workspace', async ({ page }) => {
    const buffer = makeMinimalPcapBuffer()
    await loadUniversalFiles(page, {
      name: 'first.pcap',
      mimeType: 'application/octet-stream',
      buffer,
    })
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 30_000 })

    await page.getByTestId('pcap-workspace-file-input').setInputFiles({
      name: 'second.pcap',
      mimeType: 'application/octet-stream',
      buffer,
    })
    await expect(page.getByTestId('pcap-replace-dialog')).toBeVisible()
    await expect(page.getByTestId('pcap-workspace')).toContainText('first.pcap')

    await page.getByTestId('pcap-replace-cancel').click()
    await expect(page.getByTestId('pcap-replace-dialog')).toHaveCount(0)
    await expect(page.getByTestId('pcap-workspace')).toContainText('first.pcap')
  })
})
