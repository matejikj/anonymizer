/**
 * @vitest-environment node
 *
 * Step 4 — replace truncate/drop with in-place masking for diagnostic exports.
 */
import { describe, expect, it } from 'vitest'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import type { ClassicPcapHeader, PacketEnvelope } from '../../../src/pcap/domain/types'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import {
  sanitizePacket,
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  createMaskFill,
  type PacketInput,
} from '../../../src/pcap/sanitize'
import { IntentCollector } from '../../../src/pcap/discovery/intentCollector'
import { createPresetProfile } from '../../../src/pcap/profile/presets'
import { buildDeterministicPlan } from '../../../src/pcap/plan/deterministicPlanBuilder'
import { resolveSnapshotForPackets } from './pcapSessionTestHelpers'
import { buildCaptureFromPlan } from '../../../src/pcap/export/engine'
import { PlanInvariantError } from '../../../src/pcap/plan/planErrors'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

function buildEthIpTcp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const total = 14 + 20 + 20 + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + 20 + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = 6
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  const tcp = 34
  buf[tcp] = (srcPort >> 8) & 0xff
  buf[tcp + 1] = srcPort & 0xff
  buf[tcp + 2] = (dstPort >> 8) & 0xff
  buf[tcp + 3] = dstPort & 0xff
  buf[tcp + 12] = 0x50
  buf.set(payload, tcp + 20)
  return buf
}

function envelope(data: Uint8Array, index: number, originalLength?: number): PacketEnvelope {
  return {
    packetNumber: index + 1,
    timestamp: { ticks: BigInt(index), unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: originalLength ?? data.length,
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

function exportBytes(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const len = result.truncatedLength ?? original.length
  const out = original.slice(0, len)
  for (const patch of result.patches) {
    if (patch.offset < len) {
      out.set(patch.data.slice(0, len - patch.offset), patch.offset)
    }
  }
  return out
}

describe('mask fill (step 4)', () => {
  it('is deterministic for the same domain/offset and differs across domains', () => {
    const a = createMaskFill({ length: 16, packetIndex: 3, offset: 40, domain: 'export-boundary:mask-in-place' })
    const b = createMaskFill({ length: 16, packetIndex: 3, offset: 40, domain: 'export-boundary:mask-in-place' })
    const c = createMaskFill({ length: 16, packetIndex: 3, offset: 40, domain: 'reassembly:incomplete:tcp' })
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true)
    expect(Buffer.from(a).equals(Buffer.from(c))).toBe(false)
  })

  it('zeros mode is recognizable empty fill', () => {
    const z = createMaskFill({ length: 8, packetIndex: 0, offset: 0, domain: 'x', mode: 'zeros' })
    expect([...z]).toEqual([0, 0, 0, 0, 0, 0, 0, 0])
  })
})

describe('diagnostic in-place mask (step 4)', () => {
  it('masks HTTP POST body without truncating packet length', () => {
    const secret = 'CANARY-SECRET-POST-BODY'
    const text = `POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: ${secret.length}\r\n\r\n${secret}`
    const payload = latin1(text)
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 54321, 80, payload)
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    }

    const diagnostic = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping())
    expect(diagnostic.truncatedLength).toBeUndefined()
    expect(diagnostic.drop).toBe(false)
    expect(diagnostic.patches.some((p) => p.offset > 54)).toBe(true)
    const outText = new TextDecoder('ascii', { fatal: false }).decode(exportBytes(pkt, diagnostic))
    expect(outText).not.toContain(secret)
    expect(outText).not.toContain('CANARY-SECRET')
    expect(exportBytes(pkt, diagnostic).length).toBe(pkt.length)

    // Step 2: HTTP body on TCP → MASK preferred for high-privacy too (not truncate).
    const safe = sanitizePacket(input, HIGH_PRIVACY_POLICY, new SessionMapping())
    expect(safe.truncatedLength).toBeUndefined()
    expect(exportBytes(pkt, safe).length).toBe(pkt.length)
    expect(new TextDecoder('ascii', { fatal: false }).decode(exportBytes(pkt, safe))).not.toContain(secret)
  })

  it('records mask-range intents for unsupported payload', () => {
    const payload = new Uint8Array(24).fill(0xab)
    const pkt = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 33060, payload)
    const intents = new IntentCollector()
    const result = sanitizePacket(
      {
        index: 1,
        data: pkt,
        capturedLength: pkt.length,
        originalLength: pkt.length,
        linkType: 1,
      },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
      { intents },
    )
    expect(result.truncatedLength).toBeUndefined()
    const masks = intents.intents.filter((i) => i.kind === 'mask-range')
    expect(masks.length).toBeGreaterThanOrEqual(1)
    expect(masks[0]?.byteLength).toBeGreaterThan(0)
  })

  it('fail-closes unsupported link without aborting (T07 packet isolation)', () => {
    const data = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    const result = sanitizePacket(
      {
        index: 0,
        data,
        capturedLength: data.length,
        originalLength: data.length,
        linkType: 999, // unsupported link
      },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
    )
    // T07: no PlanInvariantError — entire frame masked / marked processing-failed.
    expect(result.drop).toBe(false)
    expect(result.coverage.some((c) => c.status === 'processing-failed' || c.status === 'unsupported')).toBe(true)
    expect(result.issues.some((i) => i.startsWith('isolation:') || i.includes('unsupported') || i.includes('link'))).toBe(true)
  })

  it('preserves captured/wire length relationship for already-truncated source packets', () => {
    const payload = latin1('POST /x HTTP/1.1\r\nHost: a.com\r\n\r\nSECRET-TAIL')
    const full = buildEthIpTcp([192, 168, 1, 1], [1, 2, 3, 4], 12345, 80, payload)
    const captured = full.subarray(0, full.length - 4) // snaplen-style truncation
    const result = sanitizePacket(
      {
        index: 0,
        data: captured,
        capturedLength: captured.length,
        originalLength: full.length,
        linkType: 1,
      },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
    )
    expect(result.truncatedLength).toBeUndefined()
    expect(exportBytes(captured, result).length).toBe(captured.length)
    // Must not invent the missing 4 bytes
    expect(result.patches.every((p) => p.offset + p.data.length <= captured.length)).toBe(true)
  })
})

describe('diagnostic export parity (step 4 acceptance)', () => {
  it('keeps packet count, order, and lengths; truncatedPayloads === 0', () => {
    const packets = [
      envelope(buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 33060, new Uint8Array(32).fill(0x11)), 0),
      envelope(buildEthIpTcp([10, 0, 0, 3], [10, 0, 0, 4], 50000, 33060, new Uint8Array(40).fill(0xcd)), 1),
      envelope(buildEthIpTcp([10, 0, 0, 5], [10, 0, 0, 6], 51000, 33060, latin1('proprietary-blob-payload!!')), 2),
    ]

    const profile = createPresetProfile('diagnostic')
    const policy = DIAGNOSTIC_POLICY
    const snapshot = resolveSnapshotForPackets(packets, policy, 'mask-gen', 'mask.pcap')

    const plan = buildDeterministicPlan({
      generationId: 'mask-gen',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'mask.pcap',
      packets,
      policy,
      snapshot,
      classicHeader: classicHeader(),
    })

    for (const p of plan.packets) {
      expect(p.drop).toBe(false)
      expect(p.truncatedLength).toBeUndefined()
      expect(p.originalCapturedLength).toBe(packets[p.index]!.capturedLength)
      expect(p.originalLength).toBe(packets[p.index]!.originalLength)
    }

    const built = buildCaptureFromPlan(plan, packets)
    expect(built.truncatedPayloads).toBe(0)
    expect(plan.packets.every((p) => !p.drop)).toBe(true)

    const reread = readClassicPcap(built.buffer)
    expect(reread.packets.length).toBe(packets.length)
    for (let i = 0; i < packets.length; i++) {
      expect(reread.packets[i]!.capturedLength).toBe(packets[i]!.capturedLength)
      expect(reread.packets[i]!.originalLength).toBe(packets[i]!.originalLength)
    }
  })
})
