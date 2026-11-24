import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { cs } from '../../src/i18n/cs'
import { generateClassicPcap } from '../pcap/fixtures/generate'
import { loadUniversalFiles } from './helpers/loadFiles.ts'

const root = dirname(fileURLToPath(import.meta.url))

async function assertNoCriticalA11y(page: import('@playwright/test').Page, label: string) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze()
  const blockers = results.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious')
  expect(blockers, `${label}: ${JSON.stringify(blockers, null, 2)}`).toEqual([])
}

function smallPcapBytes(): Buffer {
  try {
    return readFileSync(join(root, '../pcap/fixtures/generated/small-100.pcap'))
  } catch {
    return generateClassicPcap(20, 32)
  }
}

test.describe('PCAP mode browser matrix', () => {
  test.beforeEach(async ({ page }) => {
    // Force portable Blob export path — FSA picker would block headless e2e
    await page.addInitScript(() => {
      Object.defineProperty(window, 'showSaveFilePicker', {
        configurable: true,
        value: undefined,
      })
    })
  })

  test('universal entry loads without login and passes axe', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: cs.empty.landingLead })).toBeVisible()
    await expect(page.getByTestId('multi-source-dropzone')).toBeVisible()
    await expect(page.getByText(/login|sign in|přihlášení|oauth|sso/i)).toHaveCount(0)
    await assertNoCriticalA11y(page, 'empty')
  })

  test('load small capture → workspace + statuses + axe', async ({ page }) => {
    await page.goto('/')

    const bytes = smallPcapBytes()
    await loadUniversalFiles(page, {
      name: 'sample.pcap',
      mimeType: 'application/octet-stream',
      buffer: bytes,
    })

    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('pcap-status-bar')).toBeVisible()
    await expect(page.getByTestId('pcap-packet-grid')).toBeVisible()
    await assertNoCriticalA11y(page, 'pcap-workspace')
  })

  test('network smoke: pcap load never leaves origin', async ({ page }) => {
    await page.goto('/')
    const origin = new URL(page.url()).origin
    const crossOrigin: string[] = []
    page.on('request', (request) => {
      const url = request.url()
      if (!url.startsWith('http://') && !url.startsWith('https://')) return
      if (!url.startsWith(origin)) crossOrigin.push(url)
    })

    const bytes = smallPcapBytes()
    await loadUniversalFiles(page, {
      name: 'net.pcap',
      mimeType: 'application/octet-stream',
      buffer: bytes,
    })
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 60_000 })
    await page.waitForTimeout(500)
    expect(crossOrigin, `Cross-origin: ${crossOrigin.join(', ')}`).toEqual([])
  })

  test('must-not-leak: export download does not contain IP canary bytes', async ({ page }) => {
    await page.goto('/')

    // Craft a tiny classic PCAP with distinctive IPs 203.0.113.77 / 198.51.100.88
    const pkt = Buffer.alloc(14 + 20 + 8 + 4)
    pkt[0] = 0xff; pkt[1] = 0xff; pkt[2] = 0xff; pkt[3] = 0xff; pkt[4] = 0xff; pkt[5] = 0xff
    pkt[6] = 0xaa; pkt[7] = 0xbb; pkt[8] = 0xcc; pkt[9] = 0xdd; pkt[10] = 0xee; pkt[11] = 0xff
    pkt.writeUInt16BE(0x0800, 12)
    pkt[14] = 0x45
    pkt.writeUInt16BE(32, 16)
    pkt[23] = 17
    pkt[26] = 203; pkt[27] = 0; pkt[28] = 113; pkt[29] = 77
    pkt[30] = 198; pkt[31] = 51; pkt[32] = 100; pkt[33] = 88

    const file = Buffer.alloc(24 + 16 + pkt.length)
    file.writeUInt32LE(0xa1b2c3d4, 0)
    file.writeUInt16LE(2, 4)
    file.writeUInt16LE(4, 6)
    file.writeUInt32LE(65535, 16)
    file.writeUInt32LE(1, 20)
    file.writeUInt32LE(1700000000, 24)
    file.writeUInt32LE(0, 28)
    file.writeUInt32LE(pkt.length, 32)
    file.writeUInt32LE(pkt.length, 36)
    pkt.copy(file, 40)

    await loadUniversalFiles(page, {
      name: 'canary.pcap',
      mimeType: 'application/octet-stream',
      buffer: file,
    })
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('pcap-export')).toBeEnabled({ timeout: 30_000 })

    const downloadPromise = page.waitForEvent('download', { timeout: 60_000 })
    await page.getByTestId('pcap-export').click()
    const download = await downloadPromise
    const path = await download.path()
    expect(path).toBeTruthy()
    const out = readFileSync(path!)
    // Original canary IP bytes must not appear as a contiguous sequence
    const hay = out.toString('binary')
    expect(hay).not.toContain(Buffer.from([203, 0, 113, 77]).toString('binary'))
    expect(hay).not.toContain(Buffer.from([198, 51, 100, 88]).toString('binary'))
  })
})
