/**
 * @vitest-environment node
 *
 * Step 7 — fingerprint pseudonymization without losing diagnostic relationships.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import {
  FingerprintSession,
  addU32Mod,
  readU32,
} from '../../../src/pcap/anonymization/fingerprintSession'
import {
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  sanitizePacket,
} from '../../../src/pcap/sanitize'
import { createPresetProfile } from '../../../src/pcap/profile/presets'
import { buildDeterministicPlan } from '../../../src/pcap/plan/deterministicPlanBuilder'
import { resolveSnapshotForPackets } from './pcapSessionTestHelpers'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import type { ClassicPcapHeader, PacketEnvelope } from '../../../src/pcap/domain/types'
import { buildExportReport } from '../../../src/pcap/export/report'
import { emptyChecksumCounts } from '../../../src/pcap/checksums/types'

function buildEthIpTcp(opts: {
  srcIp: number[]
  dstIp: number[]
  srcPort: number
  dstPort: number
  seq: number
  ack: number
  ttl?: number
  window?: number
  ipId?: number
  options?: Uint8Array
}): Uint8Array {
  const opt = opts.options ?? new Uint8Array(0)
  const pad = (4 - (opt.length % 4)) % 4
  const tcpHdr = 20 + opt.length + pad
  const total = 14 + 20 + tcpHdr
  const buf = new Uint8Array(total)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  buf[16] = 0
  buf[17] = 20 + tcpHdr
  const ipId = opts.ipId ?? 0x1234
  buf[18] = (ipId >> 8) & 0xff
  buf[19] = ipId & 0xff
  buf[22] = opts.ttl ?? 64
  buf[23] = 6
  buf.set(opts.srcIp, 26)
  buf.set(opts.dstIp, 30)
  const tcp = 34
  buf[tcp] = (opts.srcPort >> 8) & 0xff
  buf[tcp + 1] = opts.srcPort & 0xff
  buf[tcp + 2] = (opts.dstPort >> 8) & 0xff
  buf[tcp + 3] = opts.dstPort & 0xff
  buf[tcp + 4] = (opts.seq >>> 24) & 0xff
  buf[tcp + 5] = (opts.seq >>> 16) & 0xff
  buf[tcp + 6] = (opts.seq >>> 8) & 0xff
  buf[tcp + 7] = opts.seq & 0xff
  buf[tcp + 8] = (opts.ack >>> 24) & 0xff
  buf[tcp + 9] = (opts.ack >>> 16) & 0xff
  buf[tcp + 10] = (opts.ack >>> 8) & 0xff
  buf[tcp + 11] = opts.ack & 0xff
  buf[tcp + 12] = ((tcpHdr / 4) << 4)
  buf[tcp + 13] = 0x10 // ACK
  const win = opts.window ?? 0x2000
  buf[tcp + 14] = (win >> 8) & 0xff
  buf[tcp + 15] = win & 0xff
  if (opt.length) buf.set(opt, tcp + 20)
  return buf
}

function apply(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function envelope(data: Uint8Array, index: number): PacketEnvelope {
  return {
    packetNumber: index + 1,
    timestamp: { ticks: BigInt(index) * 1000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

function classicHeader(): ClassicPcapHeader {
  return {
    format: CaptureFormat.ClassicPcap,
    endian: Endian.Little,
    timestampResolution: TimestampResolution.Microseconds,
    versionMajor: 2,
    versionMinor: 4,
    snapLen: 65535,
    linkType: 1,
    tzOffset: 0,
    sigfigs: 0,
  }
}

describe('FingerprintSession (step 7)', () => {
  it('keeps per-direction SEQ offsets stable and distinct', () => {
    const fp = new FingerprintSession()
    const a = fp.tcpSeqOffsetForEndpoint({
      srcIp: '10.0.0.1',
      dstIp: '10.0.0.2',
      srcPort: 40000,
      dstPort: 80,
    })
    const b = fp.tcpSeqOffsetForEndpoint({
      srcIp: '10.0.0.1',
      dstIp: '10.0.0.2',
      srcPort: 40000,
      dstPort: 80,
    })
    expect(a.forward).toBe(b.forward)
    expect(a.reverse).toBe(b.reverse)
    expect(a.forward).not.toBe(0)
  })

  it('maps IPv4 ID stably for the same datagram and never fixed-points', () => {
    const fp = new FingerprintSession()
    const a = fp.mapIpv4Id('1.1.1.1', '2.2.2.2', 17, 0xabcd)
    const b = fp.mapIpv4Id('1.1.1.1', '2.2.2.2', 17, 0xabcd)
    expect(a).toBe(b)
    expect(a).not.toBe(0xabcd)
  })
})

describe('TCP SEQ/ACK remap (step 7)', () => {
  it('shifts SEQ and peer ACK by direction offsets; preserves relative gap', () => {
    const fingerprints = new FingerprintSession()
    const mapping = new SessionMapping()
    const fwd1 = buildEthIpTcp({
      srcIp: [10, 0, 0, 1],
      dstIp: [10, 0, 0, 2],
      srcPort: 40000,
      dstPort: 80,
      seq: 1000,
      ack: 5000,
    })
    const fwd2 = buildEthIpTcp({
      srcIp: [10, 0, 0, 1],
      dstIp: [10, 0, 0, 2],
      srcPort: 40000,
      dstPort: 80,
      seq: 1160,
      ack: 5000,
    })
    const rev = buildEthIpTcp({
      srcIp: [10, 0, 0, 2],
      dstIp: [10, 0, 0, 1],
      srcPort: 80,
      dstPort: 40000,
      seq: 5000,
      ack: 1160,
    })

    const r1 = sanitizePacket(
      { index: 0, data: fwd1, capturedLength: fwd1.length, originalLength: fwd1.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { fingerprints },
    )
    const r2 = sanitizePacket(
      { index: 1, data: fwd2, capturedLength: fwd2.length, originalLength: fwd2.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { fingerprints },
    )
    const r3 = sanitizePacket(
      { index: 2, data: rev, capturedLength: rev.length, originalLength: rev.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { fingerprints },
    )

    const o1 = apply(fwd1, r1)
    const o2 = apply(fwd2, r2)
    const o3 = apply(rev, r3)
    const seq1 = readU32(o1, 38)
    const seq2 = readU32(o2, 38)
    const ack3 = readU32(o3, 42)
    expect(seq1).not.toBe(1000)
    expect((seq2 - seq1) >>> 0).toBe(160)
    expect(ack3).toBe(seq2)
    expect(r1.coverage.some((c) => c.protocol === 'tcp-seq' && c.status === 'covered')).toBe(true)
  })

  it('adjusts SACK edges with the peer SEQ offset', () => {
    // SACK option: kind=5, len=10, left=5000, right=5200
    const sack = new Uint8Array([
      5, 10,
      0x00, 0x00, 0x13, 0x88,
      0x00, 0x00, 0x14, 0x50,
      1, 1, // NOP pad to 12
    ])
    const fingerprints = new FingerprintSession()
    const pkt = buildEthIpTcp({
      srcIp: [10, 0, 0, 1],
      dstIp: [10, 0, 0, 2],
      srcPort: 40000,
      dstPort: 80,
      seq: 100,
      ack: 5000,
      options: sack,
    })
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
      { fingerprints },
    )
    const out = apply(pkt, result)
    const left = readU32(out, 34 + 20 + 2)
    const right = readU32(out, 34 + 20 + 6)
    const ack = readU32(out, 42)
    expect(left).toBe(ack) // both use reverse offset from original 5000
    expect((right - left) >>> 0).toBe(200)
    expect(left).not.toBe(5000)
  })
})

describe('IPv4 ID / diagnostic preserve (step 7)', () => {
  it('remaps IPv4 ID and preserves TTL/window as preserved-for-diagnostics', () => {
    const pkt = buildEthIpTcp({
      srcIp: [192, 168, 1, 1],
      dstIp: [10, 0, 0, 2],
      srcPort: 5060,
      dstPort: 5060,
      seq: 1,
      ack: 2,
      ttl: 128,
      window: 0xabcd,
      ipId: 0xbeef,
    })
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
    )
    const out = apply(pkt, result)
    expect((out[18]! << 8) | out[19]!).not.toBe(0xbeef)
    expect(out[22]).toBe(128)
    expect((out[48]! << 8) | out[49]!).toBe(0xabcd)
    expect(result.coverage.some((c) => c.protocol === 'ipv4-ttl' && c.status === 'preserved-for-diagnostics')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'tcp-window' && c.status === 'preserved-for-diagnostics')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'ipv4-id' && c.status === 'covered')).toBe(true)
  })

  it('keeps fragment group joinable under the same mapped ID', () => {
    const fingerprints = new FingerprintSession()
    const mapping = new SessionMapping()
    const mk = (fragOff: number) => {
      const buf = buildEthIpTcp({
        srcIp: [1, 2, 3, 4],
        dstIp: [5, 6, 7, 8],
        srcPort: 1000,
        dstPort: 2000,
        seq: 1,
        ack: 1,
        ipId: 0x4242,
      })
      // set fragment offset (units of 8)
      buf[20] = (fragOff >> 8) & 0x1f
      buf[21] = fragOff & 0xff
      if (fragOff === 0) buf[20] |= 0x20 // MF
      return buf
    }
    const a = mk(0)
    const b = mk(185)
    const ra = sanitizePacket(
      { index: 0, data: a, capturedLength: a.length, originalLength: a.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { fingerprints },
    )
    const rb = sanitizePacket(
      { index: 1, data: b, capturedLength: b.length, originalLength: b.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { fingerprints },
    )
    const idA = (apply(a, ra)[18]! << 8) | apply(a, ra)[19]!
    const idB = (apply(b, rb)[18]! << 8) | apply(b, rb)[19]!
    expect(idA).toBe(idB)
    expect(idA).not.toBe(0x4242)
  })
})

describe('IPv6 flow label map (step 7)', () => {
  it('remaps flow label while preserving version/TC', () => {
    const total = 14 + 40
    const buf = new Uint8Array(total)
    buf[12] = 0x86
    buf[13] = 0xdd
    // version=6, TC=0, flow=0xabcde
    buf[14] = 0x60
    buf[15] = 0x0a
    buf[16] = 0xbc
    buf[17] = 0xde
    buf[20] = 58 // next = ICMPv6
    buf[21] = 64 // hop
    const result = sanitizePacket(
      { index: 0, data: buf, capturedLength: buf.length, originalLength: buf.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
    )
    const out = apply(buf, result)
    expect(out[14] & 0xf0).toBe(0x60)
    const label = ((out[15]! & 0x0f) << 16) | (out[16]! << 8) | out[17]!
    expect(label).not.toBe(0xabcde)
    expect(result.coverage.some((c) => c.protocol === 'ipv6-flow' && c.status === 'covered')).toBe(true)
  })
})

describe('plan timestamp seed (step 7)', () => {
  it('stores opaque anchor seed on plan and omits it from export report', () => {
    const packets = [
      envelope(
        buildEthIpTcp({
          srcIp: [10, 0, 0, 1],
          dstIp: [10, 0, 0, 2],
          srcPort: 12345,
          dstPort: 80,
          seq: 1,
          ack: 1,
        }),
        0,
      ),
    ]
    const profile = createPresetProfile('diagnostic')
    const snapshot = resolveSnapshotForPackets(packets, DIAGNOSTIC_POLICY, 'step7', 'step7.pcap')
    const plan = buildDeterministicPlan({
      generationId: 'step7',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'step7.pcap',
      packets,
      policy: DIAGNOSTIC_POLICY,
      snapshot,
      classicHeader: classicHeader(),
    })
    expect(plan.timestampAnchorSeed.length).toBeGreaterThan(8)
    const report = buildExportReport({
      plan,
      exportedFileName: 'step7.anonymized.pcap',
      changedPackets: 1,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [],
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: {
        validationValid: true,
        validationIssueCount: 0,
        newBlockingIssues: [],
        preservedBaselineIssues: [],
      },
    })
    const json = JSON.stringify(report)
    expect(json).not.toContain(plan.timestampAnchorSeed)
    expect(json).not.toContain('timestampAnchorSeed')
  })
})

describe('high-privacy still normalizes TTL/window (step 7)', () => {
  it('normalizes TTL and window under high-privacy policy while mapping SEQ', () => {
    const pkt = buildEthIpTcp({
      srcIp: [192, 168, 1, 1],
      dstIp: [10, 0, 0, 2],
      srcPort: 5060,
      dstPort: 5060,
      seq: 0x11111111,
      ack: 0x22222222,
      ttl: 128,
      window: 0xabcd,
    })
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      HIGH_PRIVACY_POLICY,
      new SessionMapping(),
    )
    const out = apply(pkt, result)
    expect(out[22]).toBe(64)
    expect((out[48]! << 8) | out[49]!).toBe(0x2000)
    expect(readU32(out, 38)).not.toBe(0x11111111)
  })
})
