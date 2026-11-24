/**
 * Enterprise step 11 — one engine, two classification policy tables.
 */

import { describe, expect, it } from 'vitest'
import {
  FIELD_CLASSIFICATIONS,
  DIAGNOSTIC_CLASSIFICATION_POLICY,
  HIGH_PRIVACY_CLASSIFICATION_POLICY,
  actionForClassification,
  applyPolicy,
  forbidsPacketDrop,
  SANITIZATION_PIPELINE_STAGES,
  sanitizationPolicyRealizesTable,
  expectedTimestampsMode,
  resolveExportGate,
  type SensitiveField,
} from '../../../src/pcap/trust'
import {
  DEFAULT_PCAP_LEVEL,
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  PCAP_ANONYMIZATION_LEVELS,
  levelToMapping,
  presetToSanitizationPolicy,
} from '../../../src/pcap/profile/presets'
import { resolveCoverageDisposition } from '../../../src/pcap/sanitize/coverageDisposition'
import { sanitizePacket, type PacketInput } from '../../../src/pcap/sanitize'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'

/** Canonical parser output — same fields for both profiles. */
const SAMPLE_FIELDS: readonly SensitiveField[] = [
  { type: 'ipv4', start: 26, length: 4, classification: 'IDENTITY' },
  { type: 'sip-call-id', start: 100, length: 16, classification: 'IDENTITY' },
  { type: 'authorization', start: 200, length: 32, classification: 'SECRET' },
  { type: 'rtp-payload', start: 300, length: 160, classification: 'MEDIA' },
  { type: 'http-body-unknown', start: 500, length: 64, classification: 'UNKNOWN_UNVERIFIED' },
  { type: 'ipv4-ttl', start: 22, length: 1, classification: 'FINGERPRINT' },
  { type: 'timestamp', start: 0, length: 8, classification: 'TIMING' },
  { type: 'tls-app-data', start: 600, length: 40, classification: 'ENCRYPTED_OPAQUE' },
  { type: 'tcp-flags', start: 47, length: 1, classification: 'SAFE_METADATA' },
]

function buildEthIpUdp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const total = 14 + 20 + 8 + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + 8 + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = 17
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  const udp = 34
  buf[udp] = (srcPort >> 8) & 0xff
  buf[udp + 1] = srcPort & 0xff
  buf[udp + 2] = (dstPort >> 8) & 0xff
  buf[udp + 3] = dstPort & 0xff
  const udpLen = 8 + payload.length
  buf[udp + 4] = (udpLen >> 8) & 0xff
  buf[udp + 5] = udpLen & 0xff
  buf.set(payload, udp + 8)
  return buf
}

describe('enterprise step 11 — two profiles + policy tables', () => {
  it('UI / product model: exactly two levels; default diagnostic', () => {
    expect(PCAP_ANONYMIZATION_LEVELS).toEqual(['diagnostic', 'high-privacy'])
    expect(PCAP_ANONYMIZATION_LEVELS).toHaveLength(2)
    expect(DEFAULT_PCAP_LEVEL).toBe('diagnostic')
  })

  it('pipeline is one engine with applyPolicy stage (not two anonymizers)', () => {
    expect(SANITIZATION_PIPELINE_STAGES).toEqual([
      'parse',
      'reassembly',
      'classify',
      'applyPolicy',
      'rewrite',
      'checksums',
      'verify',
    ])
  })

  it('same SensitiveField[] + two policies → expected actions', () => {
    const diagnostic = applyPolicy('diagnostic', SAMPLE_FIELDS)
    const highPrivacy = applyPolicy('high-privacy', SAMPLE_FIELDS)

    expect(diagnostic.map((f) => f.action)).toEqual([
      'MAP',
      'MAP',
      'MASK',
      'MASK',
      'MASK',
      'KEEP',
      'RELATIVE',
      'PRESERVE',
      'KEEP',
    ])
    expect(highPrivacy.map((f) => f.action)).toEqual([
      'MAP',
      'MAP',
      'MASK',
      'DROP',
      'MASK',
      'NORMALIZE',
      'ENUMERATE',
      'PRESERVE',
      'KEEP',
    ])

    // Shared: secrets MASK, encrypted PRESERVE, identity MAP
    for (const pair of [
      [diagnostic[2], highPrivacy[2]],
      [diagnostic[7], highPrivacy[7]],
      [diagnostic[0], highPrivacy[0]],
    ] as const) {
      expect(pair[0]!.action).toBe(pair[1]!.action)
    }

    // Differ: MEDIA and FINGERPRINT / TIMING
    expect(diagnostic[3]!.action).toBe('MASK')
    expect(highPrivacy[3]!.action).toBe('DROP')
    expect(diagnostic[5]!.action).toBe('KEEP')
    expect(highPrivacy[5]!.action).toBe('NORMALIZE')
  })

  it('high-privacy UNKNOWN_UNVERIFIED: TCP prefers MASK; independent datagram may DROP', () => {
    expect(
      actionForClassification('high-privacy', 'UNKNOWN_UNVERIFIED', { transport: 'tcp' }),
    ).toBe('MASK')
    expect(
      actionForClassification('high-privacy', 'UNKNOWN_UNVERIFIED', {
        independentDatagram: true,
        transport: 'udp',
      }),
    ).toBe('DROP')
    expect(
      actionForClassification('diagnostic', 'UNKNOWN_UNVERIFIED', { independentDatagram: true }),
    ).toBe('MASK')
  })

  it('diagnostic forbids packet DROP; high-privacy allows media DROP', () => {
    expect(forbidsPacketDrop('diagnostic')).toBe(true)
    expect(forbidsPacketDrop('high-privacy')).toBe(false)
    expect(DIAGNOSTIC_CLASSIFICATION_POLICY.MEDIA).toBe('MASK')
    expect(HIGH_PRIVACY_CLASSIFICATION_POLICY.MEDIA).toBe('DROP')
  })

  it('built-in SanitizationPolicy realizes classification tables + TIMING mapping', () => {
    expect(sanitizationPolicyRealizesTable(DIAGNOSTIC_POLICY).ok).toBe(true)
    expect(sanitizationPolicyRealizesTable(HIGH_PRIVACY_POLICY).ok).toBe(true)
    expect(levelToMapping('diagnostic').timestamps).toBe(expectedTimestampsMode('diagnostic'))
    expect(levelToMapping('high-privacy').timestamps).toBe(expectedTimestampsMode('high-privacy'))
    expect(presetToSanitizationPolicy('diagnostic')).toBe(DIAGNOSTIC_POLICY)
    expect(presetToSanitizationPolicy('high-privacy')).toBe(HIGH_PRIVACY_POLICY)
  })

  it('coverage disposition follows MEDIA table (diagnostic strip vs HP drop)', () => {
    expect(
      resolveCoverageDisposition(DIAGNOSTIC_POLICY, 'unsupported', 'rtp'),
    ).toBe('strip-media-payload')
    expect(
      resolveCoverageDisposition(HIGH_PRIVACY_POLICY, 'unsupported', 'rtp'),
    ).toBe('drop')
    expect(
      resolveCoverageDisposition(DIAGNOSTIC_POLICY, 'unsupported', 'application'),
    ).toBe('mask-in-place')
  })

  it('diagnostic without AI_READY is not shareable with AI', () => {
    const incomplete = resolveExportGate({
      profile: 'diagnostic',
      sanitizationIncomplete: true,
    })
    expect(incomplete.gate).toBe('NOT_AI_READY')
    expect(incomplete.safeForAi).toBe(false)
    expect(incomplete.exportAllowed).toBe(false)

    const ok = resolveExportGate({
      profile: 'diagnostic',
      sanitizationIncomplete: false,
    })
    expect(ok.gate).toBe('AI_READY')
    expect(ok.safeForAi).toBe(true)
  })

  it('same engine path: both policies sanitize the same packet shape', () => {
    const payload = new TextEncoder().encode('GET /x HTTP/1.0\r\nHost: secret.example\r\n\r\n')
    const pkt = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, payload)
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    }
    const mapping = new SessionMapping()
    const d = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping)
    const h = sanitizePacket(input, HIGH_PRIVACY_POLICY, new SessionMapping())
    expect(d.drop).toBe(false)
    // Both run the same sanitizer; HP may truncate/drop more aggressively on unknowns.
    expect(d.coverage.length).toBeGreaterThan(0)
    expect(h.coverage.length).toBeGreaterThan(0)
    expect(FIELD_CLASSIFICATIONS).toHaveLength(8)
  })
})
