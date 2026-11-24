/**
 * Enterprise step 3 — stateful TCP reassembly mandatory corpus.
 *
 * split-at-every-byte / retransmitted-secret / out-of-order-secret /
 * overlapping-segments-secret / missing-middle-segment
 */

import { describe, expect, it } from 'vitest'
import { TcpStreamReassembler } from '../../../src/pcap/reassembly/tcpStream'
import { projectPatch } from '../../../src/pcap/reassembly/patchProject'
import { runCaptureReassembly, applyReassemblyPatchesToResults, mergePacketWithReassemblyOverlay } from '../../../src/pcap/reassembly/capturePhase'
import { DEFAULT_REASSEMBLY_LIMITS } from '../../../src/pcap/reassembly/limits'
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, type PacketInput } from '../../../src/pcap/sanitize'
import { mergePatchesStrict } from '../../../src/pcap/plan/mergePatchesStrict'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import type { PacketSanitizationResult } from '../../../src/pcap/sanitize/types'

const SECRET = 'SECRETTOKEN'
const LIMITS = { ...DEFAULT_REASSEMBLY_LIMITS, maxConcurrentFlows: 32, maxBytesPerFlow: 64 * 1024 }

function latin1(s: string): Uint8Array {
  return new Uint8Array(Array.from(s, (c) => c.charCodeAt(0) & 0xff))
}

function buildEthIpTcp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  seq: number,
  payload: Uint8Array,
): Uint8Array {
  const tcpLen = 20
  const total = 14 + 20 + tcpLen + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + tcpLen + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = 6
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  const tcpStart = 34
  buf[tcpStart] = (srcPort >> 8) & 0xff
  buf[tcpStart + 1] = srcPort & 0xff
  buf[tcpStart + 2] = (dstPort >> 8) & 0xff
  buf[tcpStart + 3] = dstPort & 0xff
  buf[tcpStart + 4] = (seq >> 24) & 0xff
  buf[tcpStart + 5] = (seq >> 16) & 0xff
  buf[tcpStart + 6] = (seq >> 8) & 0xff
  buf[tcpStart + 7] = seq & 0xff
  buf[tcpStart + 12] = 0x50
  buf.set(payload, tcpStart + 20)
  return buf
}

function httpWithSecret(): Uint8Array {
  const body = `{"token":"${SECRET}"}`
  const text =
    `POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n` +
    `Content-Length: ${body.length}\r\n\r\n${body}`
  return latin1(text)
}

function envelope(data: Uint8Array, index: number): PacketEnvelope {
  return {
    packetNumber: index,
    timestamp: { ticks: BigInt(index), unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 24,
    data,
  }
}

function exportBytes(pkt: Uint8Array, result: { patches: { offset: number; data: Uint8Array }[]; truncatedLength?: number }): Uint8Array {
  const len = result.truncatedLength ?? pkt.length
  const out = pkt.slice(0, len)
  for (const patch of result.patches) {
    if (patch.offset < len) {
      out.set(patch.data.subarray(0, Math.min(patch.data.length, len - patch.offset)), patch.offset)
    }
  }
  return out
}

function decodeAscii(buf: Uint8Array): string {
  return new TextDecoder('ascii', { fatal: false }).decode(buf)
}

function sanitizeCapture(packets: PacketEnvelope[]): PacketSanitizationResult[] {
  const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY, LIMITS)
  const mapping = new SessionMapping()
  const results: PacketSanitizationResult[] = packets.map((pkt, index) => {
    const input: PacketInput = {
      index,
      data: pkt.data,
      capturedLength: pkt.capturedLength,
      originalLength: pkt.originalLength,
      linkType: pkt.linkType,
    }
    const base = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping, { reassemblyContext: reassembly })
    const overlay = reassembly.overlayFor(index)
    const merged = mergePacketWithReassemblyOverlay(base, overlay)
    return {
      packetIndex: index,
      patches: mergePatchesStrict(pkt.data.length, index, merged.patches),
      truncatedLength: merged.truncatedLength,
      coverage: merged.coverage,
      drop: merged.drop,
      issues: merged.issues,
    }
  })
  applyReassemblyPatchesToResults(results, reassembly, mapping, packets)
  return results
}

describe('enterprise step 3 — TCP reassembly multi-occurrence provenance', () => {
  it('records alternate provenance for identical retransmission', () => {
    const payload = latin1(SECRET)
    const pkt0 = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000, payload)
    const pkt1 = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000, payload)
    const data = [pkt0, pkt1]
    const tcp = new TcpStreamReassembler(LIMITS)
    const endpoint = { srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 40000, dstPort: 80, ipProto: 6 }
    tcp.ingest({ packetIndex: 0, endpoint, seq: 1000, payloadOffset: 54, payloadLength: payload.length, syn: false, fin: false, rst: false, isFragment: false })
    tcp.ingest({ packetIndex: 1, endpoint, seq: 1000, payloadOffset: 54, payloadLength: payload.length, syn: false, fin: false, rst: false, isFragment: false })

    const views = tcp.assembleAll(data)
    expect(views).toHaveLength(1)
    expect(views[0]!.status).toBe('complete')
    expect(views[0]!.packetIndices).toEqual([0, 1])
    // Primary + alternate provenance covering the same logical range.
    const covering = views[0]!.provenance.filter(
      (p) => p.assembledOffset <= 0 && p.assembledOffset + p.length >= SECRET.length,
    )
    expect(covering.length).toBeGreaterThanOrEqual(2)
    expect(new Set(covering.map((p) => p.packetIndex))).toEqual(new Set([0, 1]))

    const mask = latin1('*'.repeat(SECRET.length))
    const projected = projectPatch(views[0]!.provenance, 0, mask)
    expect(projected.map((p) => p.packetIndex).sort()).toEqual([0, 1])
  })
})

describe('enterprise step 3 — mandatory corpus (HTTP over TCP)', () => {
  it('split-at-every-byte: SECRETTOKEN gone; diagnostic length preserved', () => {
    const full = httpWithSecret()
    const packets: PacketEnvelope[] = []
    let seq = 1000
    for (let i = 0; i < full.length; i++) {
      const byte = full.subarray(i, i + 1)
      packets.push(envelope(buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, seq, byte), i))
      seq += 1
    }

    const results = sanitizeCapture(packets)
    expect(results.every((r) => r.drop === false)).toBe(true)
    expect(results.every((r) => r.truncatedLength === undefined)).toBe(true)

    for (let i = 0; i < packets.length; i++) {
      const exported = exportBytes(packets[i]!.data, results[i]!)
      expect(exported.length).toBe(packets[i]!.data.length)
      expect(decodeAscii(exported)).not.toContain(SECRET)
    }
    // Stream as a whole must not reconstruct the secret either.
    const stream = packets.map((p, i) => exportBytes(p.data, results[i]!).subarray(54)).reduce((a, b) => {
      const out = new Uint8Array(a.length + b.length)
      out.set(a, 0)
      out.set(b, a.length)
      return out
    }, new Uint8Array(0))
    expect(decodeAscii(stream)).not.toContain(SECRET)
  })

  it('retransmitted-secret: SECRETTOKEN removed from original and retransmission', () => {
    const full = httpWithSecret()
    const mid = Math.floor(full.length / 2)
    const part1 = full.subarray(0, mid)
    const part2 = full.subarray(mid)
    const packets = [
      envelope(buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000, part1), 0),
      envelope(buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000 + mid, part2), 1),
      // Retransmit of part2 (identical).
      envelope(buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000 + mid, part2), 2),
    ]

    const results = sanitizeCapture(packets)
    for (let i = 0; i < packets.length; i++) {
      expect(decodeAscii(exportBytes(packets[i]!.data, results[i]!))).not.toContain(SECRET)
      expect(exportBytes(packets[i]!.data, results[i]!).length).toBe(packets[i]!.data.length)
    }
  })

  it('out-of-order-secret: SECRETTOKEN gone when segments arrive reversed', () => {
    const full = httpWithSecret()
    const mid = Math.floor(full.length / 2)
    const part1 = full.subarray(0, mid)
    const part2 = full.subarray(mid)
    // Capture order: part2 first, then part1.
    const packets = [
      envelope(buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000 + mid, part2), 0),
      envelope(buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000, part1), 1),
    ]

    const results = sanitizeCapture(packets)
    for (let i = 0; i < packets.length; i++) {
      expect(decodeAscii(exportBytes(packets[i]!.data, results[i]!))).not.toContain(SECRET)
      expect(exportBytes(packets[i]!.data, results[i]!).length).toBe(packets[i]!.data.length)
    }
  })

  it('overlapping-segments-secret: identical overlap copies all sanitized', () => {
    const full = httpWithSecret()
    const a = full.subarray(0, Math.floor(full.length * 0.6))
    const b = full.subarray(Math.floor(full.length * 0.4)) // overlaps middle
    const packets = [
      envelope(buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000, a), 0),
      envelope(
        buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000 + Math.floor(full.length * 0.4), b),
        1,
      ),
    ]

    const results = sanitizeCapture(packets)
    for (let i = 0; i < packets.length; i++) {
      expect(decodeAscii(exportBytes(packets[i]!.data, results[i]!))).not.toContain(SECRET)
      expect(exportBytes(packets[i]!.data, results[i]!).length).toBe(packets[i]!.data.length)
    }
  })

  it('missing-middle-segment: gap → MASK present bytes (never passthrough secret fragments)', () => {
    const full = httpWithSecret()
    const third = Math.floor(full.length / 3)
    const part1 = full.subarray(0, third)
    const part3 = full.subarray(2 * third)
    // Middle third missing from capture.
    const packets = [
      envelope(buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000, part1), 0),
      envelope(buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000 + 2 * third, part3), 1),
    ]

    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY, LIMITS)
    expect(reassembly.views.some((v) => v.status === 'gap')).toBe(true)

    const results = sanitizeCapture(packets)
    for (let i = 0; i < packets.length; i++) {
      const exported = exportBytes(packets[i]!.data, results[i]!)
      expect(exported.length).toBe(packets[i]!.data.length)
      expect(decodeAscii(exported)).not.toContain(SECRET)
      // Present TCP payload must be masked (redacted), not left as plaintext fragments.
      expect(reassembly.overlayFor(i)?.skipAppLayer).toBe(true)
    }
  })

  it('RESOURCE_LIMIT_FALLBACK: limit-exceeded masks (never leave-original)', () => {
    const full = httpWithSecret()
    const packets = [
      envelope(buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1000, full), 0),
    ]
    const tiny = { ...LIMITS, maxBytesPerFlow: 8, maxHttpDecodedSize: 8 }
    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY, tiny)
    expect(reassembly.limitExceeded || reassembly.views.some((v) => v.status === 'limit-exceeded')).toBe(true)
    const overlay = reassembly.overlayFor(0)
    expect(overlay?.issues.some((i) => i.includes('RESOURCE_LIMIT_FALLBACK'))).toBe(true)
    expect(overlay?.skipAppLayer).toBe(true)
    if (overlay && overlay.patches.length > 0) {
      const exported = exportBytes(packets[0]!.data, { patches: [...overlay.patches] })
      expect(decodeAscii(exported)).not.toContain(SECRET)
    }
  })
})
