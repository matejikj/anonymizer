/**
 * T12 — phase-1 local regression gate over gitignored `anonymizer/logs/` fixtures.
 * Same skip mode as dt.pcap: absent files → skip, never commit anonymized output or raw seeds.
 *
 * Expected fixtures (when available):
 *   logs/hi2-20261012-001-sip.pcap
 *   logs/obc2.pcap
 *   logs/obc2.pcap.gz
 *   logs/obc2.log.gz
 * Optional later: Grandstream Call-ID capture, production MGCP capture.
 */

import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { validateClassicPcap } from '../../../src/pcap/capture/validator'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { assertCaptureHasNoPrivacyLeaks, assertSidecarHasNoPrivacyLeaks } from '../helpers/privacyLeakScan'
import { decompressGzipToFile } from '../../../src/correlation/import/decompressInput'
import { analyze } from '../../../src/engine/analyze'

const LOGS = join(import.meta.dirname ?? '.', '../../../logs')

const HI2_PCAP = join(LOGS, 'hi2-20261012-001-sip.pcap')
const OBC2_PCAP = join(LOGS, 'obc2.pcap')
const OBC2_PCAP_GZ = join(LOGS, 'obc2.pcap.gz')
const OBC2_LOG_GZ = join(LOGS, 'obc2.log.gz')

/** Runtime seeds from the fixture only — never hardcode customer values. */
function collectPcapPrivacySeeds(bytes: Uint8Array): string[] {
  const text = new TextDecoder('latin1').decode(bytes)
  const seeds = new Set<string>()
  for (const m of text.matchAll(/\r\no=\S+\s+(\d{8,})\s+\d+/g)) seeds.add(m[1]!)
  for (const m of text.matchAll(/\bCall-ID:\s*(\S+)/gi)) {
    const v = m[1]!.replace(/[\r\n]+$/, '')
    if (v.length >= 8) seeds.add(v)
  }
  for (const m of text.matchAll(/\b(?:From|To|Contact):\s*[^\r\n]*?sip:([^@\s;>]+)@/gi)) {
    const user = m[1]!
    if (user.length >= 4 && !/^\d+$/.test(user)) seeds.add(user)
  }
  for (const m of text.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)) {
    const ip = m[1]!
    // Skip obvious non-host noise (0.0.0.0 / 255.255.255.255 already preserved by mapping).
    if (ip === '0.0.0.0' || ip === '255.255.255.255') continue
    seeds.add(ip)
  }
  return [...seeds]
}

function collectTextPrivacySeeds(original: string): string[] {
  const seeds = new Set<string>()
  for (const m of original.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)) {
    const ip = m[1]!
    if (ip === '0.0.0.0' || ip === '255.255.255.255') continue
    seeds.add(ip)
  }
  for (const m of original.matchAll(/\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g)) {
    seeds.add(m[1]!)
  }
  return [...seeds]
}

async function inflateGzipFixture(path: string, displayName: string): Promise<Uint8Array> {
  const raw = readFileSync(path)
  const file = new File([raw], displayName, { type: 'application/gzip' })
  const inflated = await decompressGzipToFile(file)
  const ab = await inflated.file.arrayBuffer()
  return new Uint8Array(ab)
}

function assertPcapBothLevels(bytes: Uint8Array, label: string): void {
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
  const { packets } = readClassicPcap(buffer)
  expect(packets.length, `${label}: packets`).toBeGreaterThan(0)
  const seeds = collectPcapPrivacySeeds(bytes)
  expect(seeds.length, `${label}: runtime seeds`).toBeGreaterThan(0)

  for (const level of ['diagnostic', 'high-privacy'] as const) {
    const result = runExportPipeline(
      packets,
      level,
      `${label}-${level}.pcap`,
      `t12-${label}-${level}`,
      { mappingSeed: `t12-${label}-${level}` },
    )
    expect(result.plan.incidents?.totalFailures ?? 0, `${label}/${level}: incidents`).toBe(0)
    const validation = validateClassicPcap(result.built.buffer)
    expect(validation.valid, `${label}/${level}: validateClassicPcap`).toBe(true)
    if (level === 'diagnostic') {
      expect(result.built.packets.length).toBe(packets.length)
    }
    assertCaptureHasNoPrivacyLeaks(result.built.buffer, seeds)
    assertSidecarHasNoPrivacyLeaks(result.reportJson, seeds)
    assertSidecarHasNoPrivacyLeaks(result.aiDiagnosticsJson, seeds)
  }
}

describe('T12 phase-1 local regression gate', () => {
  it.skipIf(!existsSync(HI2_PCAP))(
    'hi2 SIP pcap: both levels, no incidents, leak-free',
    { timeout: 120_000 },
    () => {
      assertPcapBothLevels(new Uint8Array(readFileSync(HI2_PCAP)), 'hi2')
    },
  )

  it.skipIf(!existsSync(OBC2_PCAP))(
    'obc2 pcap: both levels, no incidents, leak-free',
    { timeout: 180_000 },
    () => {
      assertPcapBothLevels(new Uint8Array(readFileSync(OBC2_PCAP)), 'obc2')
    },
  )

  it.skipIf(!existsSync(OBC2_PCAP_GZ))(
    'obc2.pcap.gz: inflate then both levels',
    { timeout: 180_000 },
    async () => {
      const bytes = await inflateGzipFixture(OBC2_PCAP_GZ, 'obc2.pcap.gz')
      assertPcapBothLevels(bytes, 'obc2-gz')
    },
  )

  it.skipIf(!existsSync(OBC2_LOG_GZ))(
    'obc2.log.gz: inflate + text analyze without leaking seeds',
    { timeout: 120_000 },
    async () => {
      const bytes = await inflateGzipFixture(OBC2_LOG_GZ, 'obc2.log.gz')
      const original = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
      expect(original.length).toBeGreaterThan(0)
      const seeds = collectTextPrivacySeeds(original)
      const result = analyze(original)
      expect(result.anonymized.length).toBeGreaterThan(0)
      const lower = result.anonymized.toLowerCase()
      for (const seed of seeds) {
        if (seed.length < 4) continue
        expect(lower, `text leak: ${seed}`).not.toContain(seed.toLowerCase())
      }
    },
  )

  it('documents optional fixtures still missing from the local corpus', () => {
    // Grandstream Call-ID (IP encoded in Call-ID) and production MGCP captures are requested
    // in T12/D7; when added under logs/, extend this gate the same skipIf way.
    expect(true).toBe(true)
  })
})
