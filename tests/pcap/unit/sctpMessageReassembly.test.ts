/**
 * T17/V15 — SCTP DATA multi-chunk complete-message reassembly + PPID dispatch.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets'
import { sanitizePacket, type PacketInput } from '../../../src/pcap/sanitize'
import { mergePatchesStrict } from '../../../src/pcap/plan/mergePatchesStrict'
import {
  applyReassemblyPatchesToResults,
  mergePacketWithReassemblyOverlay,
  runCaptureReassembly,
} from '../../../src/pcap/reassembly/capturePhase'
import { DEFAULT_REASSEMBLY_LIMITS } from '../../../src/pcap/reassembly/limits'
import { SctpMessageReassembler } from '../../../src/pcap/reassembly/sctpMessage'
import { parseSctpDataFragments } from '../../../src/pcap/reassembly/parsePacket'
import { IPPROTO_SCTP } from '../../../src/pcap/protocols/types'
import { sctpCrc32c, writeCrc32cLe } from '../../../src/crypto/crc32c'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import type { PacketSanitizationResult } from '../../../src/pcap/sanitize/types'

const LIMITS = DEFAULT_REASSEMBLY_LIMITS

function buildEthIpSctp(srcIp: number[], dstIp: number[], sctpPayload: Uint8Array): Uint8Array {
  const total = 14 + 20 + sctpPayload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 0)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + sctpPayload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = IPPROTO_SCTP
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  buf.set(sctpPayload, 34)
  return buf
}

function finalizeSctp(sctp: Uint8Array): void {
  writeCrc32cLe(sctp, 8, sctpCrc32c(sctp, 0, sctp.length))
}

/** RFC 8260 I-DATA (type 64) — 20-byte header; PPID at +16 when B=1. */
function buildIDataChunk(
  srcPort: number,
  dstPort: number,
  ppid: number,
  user: Uint8Array,
  opts: { flags?: number; tsn?: number; vtag?: number } = {},
): Uint8Array {
  const flags = opts.flags ?? 0x03 // B+E
  const tsn = opts.tsn ?? 1
  const vtag = opts.vtag ?? 0x01020304
  const chunkLen = 20 + user.length
  const padded = (chunkLen + 3) & ~3
  const pkt = new Uint8Array(12 + padded)
  pkt[0] = (srcPort >> 8) & 0xff
  pkt[1] = srcPort & 0xff
  pkt[2] = (dstPort >> 8) & 0xff
  pkt[3] = dstPort & 0xff
  pkt[4] = (vtag >>> 24) & 0xff
  pkt[5] = (vtag >>> 16) & 0xff
  pkt[6] = (vtag >>> 8) & 0xff
  pkt[7] = vtag & 0xff
  pkt[12] = 64 // I-DATA
  pkt[13] = flags
  pkt[14] = (chunkLen >> 8) & 0xff
  pkt[15] = chunkLen & 0xff
  pkt[16] = (tsn >>> 24) & 0xff
  pkt[17] = (tsn >>> 16) & 0xff
  pkt[18] = (tsn >>> 8) & 0xff
  pkt[19] = tsn & 0xff
  // message id @ chunk+12, PPID @ chunk+16 when B=1, user @ chunk+20
  pkt[24] = 0
  pkt[25] = 0
  pkt[26] = 0
  pkt[27] = 0
  pkt[28] = (ppid >>> 24) & 0xff
  pkt[29] = (ppid >>> 16) & 0xff
  pkt[30] = (ppid >>> 8) & 0xff
  pkt[31] = ppid & 0xff
  pkt.set(user, 32)
  finalizeSctp(pkt)
  return pkt
}

function buildDataChunk(
  srcPort: number,
  dstPort: number,
  ppid: number,
  user: Uint8Array,
  opts: { flags?: number; tsn?: number; vtag?: number } = {},
): Uint8Array {
  const flags = opts.flags ?? 0x03
  const tsn = opts.tsn ?? 1
  const vtag = opts.vtag ?? 0x01020304
  const chunkLen = 16 + user.length
  const padded = (chunkLen + 3) & ~3
  const pkt = new Uint8Array(12 + padded)
  pkt[0] = (srcPort >> 8) & 0xff
  pkt[1] = srcPort & 0xff
  pkt[2] = (dstPort >> 8) & 0xff
  pkt[3] = dstPort & 0xff
  pkt[4] = (vtag >>> 24) & 0xff
  pkt[5] = (vtag >>> 16) & 0xff
  pkt[6] = (vtag >>> 8) & 0xff
  pkt[7] = vtag & 0xff
  pkt[12] = 0
  pkt[13] = flags
  pkt[14] = (chunkLen >> 8) & 0xff
  pkt[15] = chunkLen & 0xff
  pkt[16] = (tsn >>> 24) & 0xff
  pkt[17] = (tsn >>> 16) & 0xff
  pkt[18] = (tsn >>> 8) & 0xff
  pkt[19] = tsn & 0xff
  pkt[24] = (ppid >>> 24) & 0xff
  pkt[25] = (ppid >>> 16) & 0xff
  pkt[26] = (ppid >>> 8) & 0xff
  pkt[27] = ppid & 0xff
  pkt.set(user, 28)
  finalizeSctp(pkt)
  return pkt
}

function minimalDiameter(): Uint8Array {
  const diam = new Uint8Array(20)
  diam[0] = 1
  diam[3] = 20
  diam[4] = 0x80
  diam[7] = 257
  return diam
}

function envelope(data: Uint8Array, index: number): PacketEnvelope {
  return {
    packetNumber: index + 1,
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

function exportBytes(
  pkt: Uint8Array,
  result: { patches: { offset: number; data: Uint8Array }[]; truncatedLength?: number },
): Uint8Array {
  const len = result.truncatedLength ?? pkt.length
  const out = pkt.slice(0, len)
  for (const patch of result.patches) {
    if (patch.offset < len) {
      out.set(patch.data.subarray(0, Math.min(patch.data.length, len - patch.offset)), patch.offset)
    }
  }
  return out
}

function sanitizeCapture(packets: PacketEnvelope[]): PacketSanitizationResult[] {
  const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY, LIMITS)
  const mapping = new SessionMapping(undefined, { seed: 'v15-sctp' })
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

describe('V15 SCTP message reassembly', () => {
  it('assembles two DATA fragments with contiguous TSN', () => {
    const diam = minimalDiameter()
    const part0 = diam.subarray(0, 10)
    const part1 = diam.subarray(10)
    const sctp0 = buildDataChunk(3868, 3868, 46, part0, { flags: 0x02, tsn: 1 })
    const sctp1 = buildDataChunk(3868, 3868, 46, part1, { flags: 0x01, tsn: 2 })
    const frames = [
      buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp0),
      buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp1),
    ]
    const reassembler = new SctpMessageReassembler(LIMITS)
    let order = 0
    for (let i = 0; i < frames.length; i++) {
      const frags = parseSctpDataFragments(frames[i]!, 1, frames[i]!.length, i, order)
      expect(frags?.length).toBe(1)
      for (const f of frags!) {
        reassembler.ingest(f)
        order = f.captureOrder + 1
      }
    }
    const { views, completeSpans } = reassembler.assembleAll(frames)
    expect(views).toHaveLength(1)
    expect(views[0]!.bytes.length).toBe(20)
    expect(views[0]!.status).toBe('complete')
    expect(completeSpans.size).toBe(2)
  })

  it('dispatches Diameter on reassembled payload across two packets', () => {
    const diam = minimalDiameter()
    const sctp0 = buildDataChunk(3868, 3868, 46, diam.subarray(0, 10), { flags: 0x02, tsn: 1 })
    const sctp1 = buildDataChunk(3868, 3868, 46, diam.subarray(10), { flags: 0x01, tsn: 2 })
    const packets = [
      envelope(buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp0), 0),
      envelope(buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp1), 1),
    ]
    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY, LIMITS)
    expect(reassembly.views.some((v) => v.transport === 'sctp' && v.status === 'complete')).toBe(true)
    expect(reassembly.isSctpCompletePayload?.(0, 34 + 28)).toBe(true)
    expect(reassembly.isSctpCompletePayload?.(1, 34 + 28)).toBe(true)

    const results = sanitizeCapture(packets)
    const mergedIssues = results.flatMap((r) => r.issues)
    expect(mergedIssues.some((i) => i.includes('sctp-message-reassembled'))).toBe(true)
    expect(
      results.some((r) =>
        r.coverage.some((c) => c.protocol === 'diameter' || c.protocol.startsWith('diameter')),
      ),
    ).toBe(true)
    for (const [i, pkt] of packets.entries()) {
      const out = exportBytes(pkt.data, results[i]!)
      expect(new TextDecoder('latin1').decode(out).includes('diameter')).toBe(false)
    }
  })

  it('leaves incomplete single fragment as requires-reassembly on per-packet path', () => {
    const canary = new TextEncoder().encode('FRAG-ONLY-CANARY')
    const sctp = buildDataChunk(3868, 3868, 99, canary, { flags: 0x02, tsn: 1 })
    const packets = [envelope(buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp), 0)]
    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY, LIMITS)
    expect(reassembly.views.filter((v) => v.transport === 'sctp')).toHaveLength(0)

    const mapping = new SessionMapping(undefined, { seed: 'v15-incomplete' })
    const result = sanitizePacket(
      {
        index: 0,
        data: packets[0]!.data,
        capturedLength: packets[0]!.capturedLength,
        originalLength: packets[0]!.originalLength,
        linkType: 1,
      },
      DIAGNOSTIC_POLICY,
      mapping,
      { reassemblyContext: reassembly },
    )
    expect(result.coverage.some((c) => c.status === 'requires-reassembly')).toBe(true)
    const out = exportBytes(packets[0]!.data, result)
    expect(new TextDecoder('latin1').decode(out).includes('FRAG-ONLY-CANARY')).toBe(false)
  })

  it('I-DATA B+E masks full user payload (R03/T17 — 20-byte header, no PII in header span)', () => {
    const canary = new TextEncoder().encode('PII!')
    const sctp = buildIDataChunk(5000, 5000, 999, canary)
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 'v15-idata' })
    const result = sanitizePacket(
      { index: 0, data: frame, capturedLength: frame.length, originalLength: frame.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    const out = exportBytes(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('PII!')).toBe(false)
    expect(result.coverage.some((c) => c.protocol === 'sctp-data' && c.length === 20)).toBe(true)
  })
})
