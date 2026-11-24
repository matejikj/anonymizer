import { test, expect } from '@playwright/test'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateClassicPcap } from '../pcap/fixtures/generate'
import { loadUniversalFiles } from './helpers/loadFiles.ts'
import { cs } from '../../src/i18n/cs.ts'
import { RECOVERY_MAGIC_ASCII } from '../../src/pcap/recovery/codec/formatConstants.ts'

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures')

function ensurePcap(): string {
  mkdirSync(fixturesDir, { recursive: true })
  const file = join(fixturesDir, 'reversed-editor-source.pcap')
  writeFileSync(file, generateClassicPcap(8, 32))
  return file
}

test.describe('PCAP deanonymization — reversed editor', () => {
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' })
    await page.addInitScript(() => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('light'))
      localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', JSON.stringify(true))
    })
  })

  test('landing shows one anonymize hero and secondary resolve/recovery utilities', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByTestId('landing-anonymize-panel')).toBeVisible()
    await expect(page.getByTestId('multi-source-dropzone')).toBeVisible()
    await expect(page.getByTestId('landing-utilities')).toBeVisible()
    await expect(page.getByTestId('resolve-return-landing-panel')).toBeVisible()
    await expect(page.getByTestId('recovery-landing-panel')).toBeVisible()
    await expect(page.getByTestId('recovery-landing-choose')).toBeVisible()
  })

  test('export recovery file, then drop the pair back in to open the reversed editor', async ({ page }) => {
    test.setTimeout(120_000)

    // Chrome (and the sandbox's Chromium/Playwright pairing) silently withholds a second
    // automatic `<a download>` triggered from one click without a fresh user gesture in
    // between — so the app now downloads the anonymized PCAP and the recovery file via two
    // separate button clicks (Export, then recovery bundle export in cs UI), each producing
    // exactly one file. Capture the real per-file bytes directly in-page, ahead of
    // `URL.createObjectURL` (what `triggerBlobDownload` calls), which sidesteps the browser's
    // download manager entirely and is more reliable in the sandbox than `Download` events.
    await page.addInitScript(() => {
      ;(window as unknown as { __capturedBlobs: Blob[] }).__capturedBlobs = []
      const orig = URL.createObjectURL.bind(URL)
      URL.createObjectURL = (obj: Blob | MediaSource) => {
        if (obj instanceof Blob) (window as unknown as { __capturedBlobs: Blob[] }).__capturedBlobs.push(obj)
        return orig(obj)
      }
    })
    await page.goto('/')
    await loadUniversalFiles(page, ensurePcap())
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 90_000 })

    const startLen = await page.evaluate(
      () => (window as unknown as { __capturedBlobs: Blob[] }).__capturedBlobs.length,
    )
    await page.getByTestId('pcap-export').click()
    await page.waitForFunction(
      (from) => (window as unknown as { __capturedBlobs: Blob[] }).__capturedBlobs.length >= from + 1,
      startLen,
      { timeout: 15_000 },
    )
    await page.getByTestId('pcap-export-recovery').click()
    await page.waitForFunction(
      (from) => (window as unknown as { __capturedBlobs: Blob[] }).__capturedBlobs.length >= from + 2,
      startLen,
      { timeout: 15_000 },
    )
    const blobsBase64: string[] = await page.evaluate(async (from) => {
      const blobs = (window as unknown as { __capturedBlobs: Blob[] }).__capturedBlobs.slice(from)
      const out: string[] = []
      for (const blob of blobs) {
        const buf = new Uint8Array(await blob.arrayBuffer())
        let binary = ''
        for (const byte of buf) binary += String.fromCharCode(byte)
        out.push(btoa(binary))
      }
      return out
    }, startLen)

    let anonPath: string | null = null
    let recoveryPath: string | null = null
    let index = 0
    for (const b64 of blobsBase64) {
      const buf = Buffer.from(b64, 'base64')
      const tmpPath = join(fixturesDir, `reversed-editor-download-${index++}.bin`)
      writeFileSync(tmpPath, buf)
      if (buf.toString('ascii', 0, RECOVERY_MAGIC_ASCII.length) === RECOVERY_MAGIC_ASCII) {
        recoveryPath = tmpPath
      } else if (buf[0] === 0xd4 && buf[1] === 0xc3 && buf[2] === 0xb2 && buf[3] === 0xa1) {
        anonPath = tmpPath
      }
    }
    expect(anonPath, 'anonymized PCAP was not captured').not.toBeNull()
    expect(recoveryPath, 'recovery file was not captured').not.toBeNull()

    await page.goto('/')
    await expect(page.getByTestId('landing')).toBeVisible()
    await page.getByTestId('recovery-file-input').setInputFiles([anonPath!, recoveryPath!])

    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('pcap-data-pane-original')).toContainText(
      cs.pcap.workspace.paneAnonymizedRecoveryTitle,
    )
    await expect(page.getByTestId('pcap-data-pane-anonymized')).toContainText(
      cs.pcap.workspace.paneDeanonymizedTitle,
    )
    await expect(page.getByTestId('pcap-download-deanonymized')).toBeVisible()
    await expect(page.getByTestId('pcap-recovery-search-open')).toBeVisible()
    await expect(page.getByTestId('pcap-export')).toHaveCount(0)

    // Packet 0's true original endpoints per `generateClassicPcap` (10.0.0.0 -> 192.168.0.0) —
    // must show the real restored addresses, not the anonymized file's own (10.254.x.x-style)
    // values and not some further re-anonymized pseudonym of them. This guards two real bugs
    // found while verifying this feature: (1) a stale-memoized packet row never re-rendering
    // after the counterpart attaches, and (2) an off-by-one between the recovery engine's
    // 1-based packet numbers and this app's 0-based `packetNumber`.
    const deanonRow0 = page.locator('[data-testid="pcap-packet-grid-anonymized"] [role="row"][data-packet-index="0"]')
    await expect(deanonRow0).toContainText('10.0.0.0')
    await expect(deanonRow0).toContainText('192.168.0.0')

    await page.getByTestId('pcap-recovery-search-open').click()
    await expect(page.getByTestId('pcap-recovery-search-dialog')).toBeVisible()
    await page.getByTestId('pcap-recovery-search-input').fill('zzz-not-a-real-anonymized-value')
    await page.getByTestId('pcap-recovery-search-submit').click()
    await expect(page.getByTestId('pcap-recovery-search-error')).toBeVisible({ timeout: 15_000 })
    await page.getByTestId('pcap-recovery-search-close').click()
    await expect(page.getByTestId('pcap-recovery-search-dialog')).toHaveCount(0)
  })
})
