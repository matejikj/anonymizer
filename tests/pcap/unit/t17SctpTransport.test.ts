/**
 * T17 — SCTP transport: CRC32c, INIT address map, PPID Diameter dispatch, fragment fail-closed.
 * V15 — complete multi-fragment DATA reassembly + PPID sanitize (canary must not leak).
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { crc32c, sctpCrc32c, writeCrc32cLe, readCrc32cLe } from '../../../src/crypto/crc32c'
import { recomputeChecksums } from '../../../src/pcap/checksums/engine'
import { listCatalogProtocols } from '../../../src/pcap/kernel/catalog'
import { IPPROTO_SCTP } from '../../../src/pcap/protocols/types'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { runCaptureReassembly } from '../../../src/pcap/reassembly/capturePhase'

function packetInput(data: Uint8Array) {
  return {
    index: 0,
    data,
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
  }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function buildEthIpSctp(
  srcIp: number[],
  dstIp: number[],
  sctpPayload: Uint8Array,
): Uint8Array {
  const total = 14 + 20 + sctpPayload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
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

function finalizeSctp(packet: Uint8Array): void {
  const crc = sctpCrc32c(packet, 0, packet.length)
  writeCrc32cLe(packet, 8, crc)
}

/** INIT with one IPv4 Address parameter carrying canary 10.9.8.7 */
function buildInitPacket(srcPort: number, dstPort: number, addr: number[]): Uint8Array {
  const param = new Uint8Array(8)
  param[0] = 0
  param[1] = 5 // IPv4 Address
  param[2] = 0
  param[3] = 8
  param.set(addr, 4)
  const chunkValue = new Uint8Array(16 + param.length)
  // initiate tag
  chunkValue[0] = 0x11
  chunkValue[1] = 0x22
  chunkValue[2] = 0x33
  chunkValue[3] = 0x44
  // a_rwnd
  chunkValue[4] = 0
  chunkValue[5] = 1
  chunkValue[6] = 0
  chunkValue[7] = 0
  // streams
  chunkValue[8] = 0
  chunkValue[9] = 1
  chunkValue[10] = 0
  chunkValue[11] = 1
  // initial TSN
  chunkValue[12] = 0xaa
  chunkValue[13] = 0xbb
  chunkValue[14] = 0xcc
  chunkValue[15] = 0xdd
  chunkValue.set(param, 16)
  const chunkLen = 4 + chunkValue.length
  const pkt = new Uint8Array(12 + chunkLen)
  pkt[0] = (srcPort >> 8) & 0xff
  pkt[1] = srcPort & 0xff
  pkt[2] = (dstPort >> 8) & 0xff
  pkt[3] = dstPort & 0xff
  // vtag
  pkt[4] = 0
  pkt[5] = 0
  pkt[6] = 0
  pkt[7] = 1
  pkt[12] = 1 // INIT
  pkt[13] = 0
  pkt[14] = (chunkLen >> 8) & 0xff
  pkt[15] = chunkLen & 0xff
  pkt.set(chunkValue, 16)
  finalizeSctp(pkt)
  return pkt
}

function buildDataChunk(
  srcPort: number,
  dstPort: number,
  ppid: number,
  user: Uint8Array,
  flags = 0x03, // B+E
  opts?: { tsn?: number; ssn?: number; vtag?: number },
): Uint8Array {
  // DATA chunk length includes 16-byte fixed header + user data
  const chunkLen = 16 + user.length
  const padded = (chunkLen + 3) & ~3
  const pkt = new Uint8Array(12 + padded)
  pkt[0] = (srcPort >> 8) & 0xff
  pkt[1] = srcPort & 0xff
  pkt[2] = (dstPort >> 8) & 0xff
  pkt[3] = dstPort & 0xff
  const vtag = opts?.vtag ?? 1
  pkt[4] = (vtag >>> 24) & 0xff
  pkt[5] = (vtag >>> 16) & 0xff
  pkt[6] = (vtag >>> 8) & 0xff
  pkt[7] = vtag & 0xff
  pkt[12] = 0 // DATA
  pkt[13] = flags
  pkt[14] = (chunkLen >> 8) & 0xff
  pkt[15] = chunkLen & 0xff
  const tsn = opts?.tsn ?? 1
  pkt[16] = (tsn >>> 24) & 0xff
  pkt[17] = (tsn >>> 16) & 0xff
  pkt[18] = (tsn >>> 8) & 0xff
  pkt[19] = tsn & 0xff
  // SID/SSN
  const ssn = opts?.ssn ?? 0
  pkt[20] = 0
  pkt[21] = 0
  pkt[22] = (ssn >> 8) & 0xff
  pkt[23] = ssn & 0xff
  // PPID
  pkt[24] = (ppid >>> 24) & 0xff
  pkt[25] = (ppid >>> 16) & 0xff
  pkt[26] = (ppid >>> 8) & 0xff
  pkt[27] = ppid & 0xff
  pkt.set(user, 28)
  finalizeSctp(pkt)
  return pkt
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
    fileOffset: 0,
    data,
  }
}

/** Minimal Diameter CER-ish with Origin-Host canary (AVP 264). */
function buildDiameterWithOriginHost(host: string): Uint8Array {
  const hostBytes = new TextEncoder().encode(host)
  const avpLen = 8 + hostBytes.length
  const pad = (4 - (avpLen % 4)) % 4
  const avp = new Uint8Array(avpLen + pad)
  avp[0] = 0
  avp[1] = 0
  avp[2] = 1
  avp[3] = 0x08 // 264
  avp[4] = 0x40
  avp[5] = (avpLen >> 16) & 0xff
  avp[6] = (avpLen >> 8) & 0xff
  avp[7] = avpLen & 0xff
  avp.set(hostBytes, 8)
  const msgLen = 20 + avp.length
  const msg = new Uint8Array(msgLen)
  msg[0] = 1
  msg[1] = (msgLen >> 16) & 0xff
  msg[2] = (msgLen >> 8) & 0xff
  msg[3] = msgLen & 0xff
  msg[4] = 0x80
  msg[5] = 0
  msg[6] = 0
  msg[7] = 257 & 0xff
  msg.set(avp, 20)
  return msg
}

describe('T17 CRC32c', () => {
  it('matches Castagnoli vector', () => {
    expect(crc32c(new TextEncoder().encode('123456789')).toString(16)).toBe('e3069283')
  })
})

describe('T17 registry', () => {
  it('registers SCTP in catalog and families', () => {
    const ids = listCatalogProtocols().map((p) => p.id)
    expect(ids).toContain('sctp')
    expect(familyForProtocol('sctp').familyId).toBe('network-headers')
    expect(PCAP_ENGINE_VERSION).toMatch(/^2\.\d+\.\d+$/)
  })
})

describe('T17 INIT / DATA', () => {
  it('maps INIT IPv4 address and recomputes CRC32c', () => {
    const sctp = buildInitPacket(3868, 3868, [10, 9, 8, 7])
    expect(readCrc32cLe(sctp, 8)).toBe(sctpCrc32c(sctp, 0, sctp.length))
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 't17-init' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'sctp')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'sctp-param-ipv4')).toBe(true)
    const out = applyPatches(frame, result)
    const report = recomputeChecksums(out, {
      linkType: 1,
      capturedLen: out.length,
      originalLen: out.length,
      patches: result.patches,
      originalData: frame,
    })
    expect(report.fields.some((f) => f.layer === 'sctp' && f.disposition === 'recomputed')).toBe(true)
    const sctpOff = 34
    const addrOff = sctpOff + 16 + 16 + 4 // common+chunk hdr+fixed init+param hdr
    expect([...out.subarray(addrOff, addrOff + 4)]).not.toEqual([10, 9, 8, 7])
    const crc = readCrc32cLe(out, sctpOff + 8)
    expect(crc).toBe(sctpCrc32c(out.subarray(sctpOff), 0, out.length - sctpOff))
  })

  it('masks unknown PPID payload canary', () => {
    const canary = new TextEncoder().encode('SECRET-SCTP-CANARY')
    const sctp = buildDataChunk(2905, 2905, 99, canary)
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 't17-ppid' })
    const out = applyPatches(frame, sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping))
    expect(new TextDecoder('latin1').decode(out).includes('SECRET-SCTP-CANARY')).toBe(false)
  })

  it('marks fragmented DATA as requires-reassembly and masks body', () => {
    const canary = new TextEncoder().encode('FRAG-CANARY-XX')
    const sctp = buildDataChunk(3868, 3868, 46, canary, 0x02) // B only
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 't17-frag' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.status === 'requires-reassembly')).toBe(true)
    expect(result.issues.some((i) => i.includes('requires-reassembly'))).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('FRAG-CANARY')).toBe(false)
  })

  it('dispatches complete Diameter PPID 46 into Diameter sanitizer', () => {
    // Minimal Diameter: version=1, length=20, flags, code, app-id, hop/end
    const diam = new Uint8Array(20)
    diam[0] = 1
    diam[1] = 0
    diam[2] = 0
    diam[3] = 20
    diam[4] = 0x80 // R
    diam[5] = 0
    diam[6] = 0
    diam[7] = 257 // CER
    const sctp = buildDataChunk(3868, 3868, 46, diam, 0x03)
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 't17-diam' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(
      result.coverage.some((c) => c.protocol === 'diameter' || c.protocol.startsWith('diameter')),
    ).toBe(true)
  })
})

describe('T17 V15 SCTP complete-message reassembly', () => {
  it('reassembles two DATA fragments and removes Diameter Origin-Host canary from export', () => {
    const canary = 'sctp-frag-pcrf.example.com'
    const diam = buildDiameterWithOriginHost(canary)
    expect(diam.length).toBeGreaterThan(24)
    const mid = Math.floor(diam.length / 2)
    const part1 = diam.subarray(0, mid)
    const part2 = diam.subarray(mid)

    const sctp1 = buildDataChunk(3868, 3868, 46, part1, 0x02, { tsn: 10, ssn: 7, vtag: 0x42 }) // B
    const sctp2 = buildDataChunk(3868, 3868, 46, part2, 0x01, { tsn: 11, ssn: 7, vtag: 0x42 }) // E
    const frame1 = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp1)
    const frame2 = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp2)
    const packets = [envelope(frame1, 0), envelope(frame2, 1)]

    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY)
    const sctpView = reassembly.views.find((v) => v.transport === 'sctp' && v.status === 'complete')
    expect(sctpView).toBeDefined()
    expect(sctpView!.bytes.length).toBe(diam.length)

    const result = runExportPipeline(packets, 'diagnostic', 't17-sctp-frag.pcap', 't17-sctp-v15', {
      mappingSeed: 't17-sctp-v15',
    })
    const text = new TextDecoder('latin1').decode(result.built.buffer)
    expect(text.includes(canary)).toBe(false)
    expect(text.includes('sctp-frag-pcrf')).toBe(false)

    const allCoverage = result.discovery.packetDiscovery
      .flatMap((p) => p.coverage ?? [])
      .filter((c): c is NonNullable<typeof c> => c != null)
    const hasDiameter = allCoverage.some(
      (c) => c.protocol === 'diameter' || c.protocol.startsWith('diameter'),
    )
    const hasReassembledIssue = result.discovery.packetDiscovery.some((p) =>
      p.issues.some((i) => i.includes('sctp-message-reassembled') || i.includes('sctp-reassembled')),
    )
    expect(hasDiameter || hasReassembledIssue).toBe(true)
    expect(allCoverage.every((c) => c.status !== 'requires-reassembly')).toBe(true)
  })

  it('keeps requires-reassembly+mask when the ending fragment is missing', () => {
    const canary = new TextEncoder().encode('INCOMPLETE-SCTP-CANARY!!')
    const sctp = buildDataChunk(3868, 3868, 46, canary, 0x02, { tsn: 1, ssn: 1 }) // B only
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const packets = [envelope(frame, 0)]
    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY)
    expect(reassembly.views.filter((v) => v.transport === 'sctp' && v.status === 'complete')).toHaveLength(0)

    const result = runExportPipeline(packets, 'diagnostic', 't17-sctp-incomplete.pcap', 't17-sctp-inc', {
      mappingSeed: 't17-sctp-inc',
    })
    const text = new TextDecoder('latin1').decode(result.built.buffer)
    expect(text.includes('INCOMPLETE-SCTP-CANARY')).toBe(false)
    const coverage = result.discovery.packetDiscovery
      .flatMap((p) => p.coverage ?? [])
      .filter((c): c is NonNullable<typeof c> => c != null)
    expect(coverage.some((c) => c.status === 'requires-reassembly')).toBe(true)
  })
})
