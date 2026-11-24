/**
 * T-01.B — share of packets with journal-backed symbolic ops on a mixed synthetic corpus.
 */
import { describe, expect, it } from 'vitest'
import { CaptureFormat, type PacketEnvelope } from '../../../src/pcap/domain/types'
import { processCapture } from '../../../src/pcap/processing/processingPipeline'
import { policyFromPreset } from '../../../src/pcap/sanitize/engine'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import { classicHeader } from '../helpers/diagnosticPipeline'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { STUN_ATTR, STUN_MAGIC_COOKIE } from '../../../src/pcap/protocols/application/stun/classify'
import { GTP_C_UDP_PORT } from '../../../src/pcap/sanitize/gtp'
import { encodeTbcd, TBCD_GSM } from '../../../src/pcap/protocols/application/binproto/tbcd'

/** Measured by vitest `T-01.B mixed corpus journal ops ratio` (update ACCEPTANCE-AUDIT-LIVE-63 T-01.B). */
export const T01B_MIXED_CORPUS_PACKET_COUNT = 5
/** Pinned ratio: packets with journal.ops.length>0 / total (mixed SIP+DNS+STUN+RADIUS+GTP corpus). */
export const T01B_MIXED_CORPUS_JOURNAL_OPS_PACKET_RATIO = 1
/** Pinned ratio: discovery frozen plans without legacyResolve / total (common-traffic corpus). */
export const T01B_MIXED_CORPUS_LEGACY_RESOLVE_FREE_RATIO = 1

function envelope(data: Uint8Array, index: number): PacketEnvelope {
  return {
    packetNumber: index + 1,
    timestamp: {
      ticks: 1_700_000_000_000_000n + BigInt(index),
      unitsPerSecond: 1_000_000n,
      offsetSeconds: 0n,
    },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

function buildDnsAResponse(ipv4: number[]): Uint8Array {
  const name = [4, ...'host'.split('').map((c) => c.charCodeAt(0)), 7, ...'example'.split('').map((c) => c.charCodeAt(0)), 3, ...'com'.split('').map((c) => c.charCodeAt(0)), 0]
  return new Uint8Array([
    0x00, 0x01,
    0x84, 0x00,
    0x00, 0x00,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    ...name,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c,
    0x00, 0x04,
    ...ipv4,
  ])
}

function buildRadiusFramedIp(ipv4: number[]): Uint8Array {
  const pkt = new Uint8Array(20 + 6)
  pkt[0] = 1
  pkt[1] = 42
  const total = pkt.length
  pkt[2] = (total >> 8) & 0xff
  pkt[3] = total & 0xff
  pkt[20] = 8
  pkt[21] = 6
  pkt.set(ipv4, 22)
  return pkt
}

function buildStunXorMappedIpv4(ip: number[], port: number): Uint8Array {
  const xPort = (port ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xffff)) & 0xffff
  const xorIp = new Uint8Array([
    ip[0]! ^ ((STUN_MAGIC_COOKIE >>> 24) & 0xff),
    ip[1]! ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xff),
    ip[2]! ^ ((STUN_MAGIC_COOKIE >>> 8) & 0xff),
    ip[3]! ^ (STUN_MAGIC_COOKIE & 0xff),
  ])
  const attrValue = new Uint8Array(8)
  attrValue[1] = 0x01
  attrValue[2] = (xPort >> 8) & 0xff
  attrValue[3] = xPort & 0xff
  attrValue.set(xorIp, 4)
  const bodyLen = 4 + 8
  const msg = new Uint8Array(20 + bodyLen)
  msg[0] = 0x01
  msg[1] = 0x01
  msg[2] = (bodyLen >> 8) & 0xff
  msg[3] = bodyLen & 0xff
  msg[4] = (STUN_MAGIC_COOKIE >>> 24) & 0xff
  msg[5] = (STUN_MAGIC_COOKIE >>> 16) & 0xff
  msg[6] = (STUN_MAGIC_COOKIE >>> 8) & 0xff
  msg[7] = STUN_MAGIC_COOKIE & 0xff
  msg[8] = 0x01
  msg[20] = (STUN_ATTR.XOR_MAPPED_ADDRESS >> 8) & 0xff
  msg[21] = STUN_ATTR.XOR_MAPPED_ADDRESS & 0xff
  msg[22] = 0x00
  msg[23] = 0x08
  msg.set(attrValue, 24)
  return msg
}

function u32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff])
}

function v2Ie(type: number, value: Uint8Array, instance = 0): Uint8Array {
  const out = new Uint8Array(4 + value.length)
  out[0] = type
  out[1] = (value.length >> 8) & 0xff
  out[2] = value.length & 0xff
  out[3] = instance & 0x0f
  out.set(value, 4)
  return out
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((s, p) => s + p.length, 0)
  const out = new Uint8Array(len)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

const GTP_F_TEID_VAL = 0x0a1b2c3d

/** GTPv2 Create Session Request (IMSI + F-TEID + PAA) — same shape as t26GtpMobileCore. */
function buildGtpCreateSessionRequest(): Uint8Array {
  const imsi = encodeTbcd('262011234567890', 8, TBCD_GSM)!
  const fTeid = concat(
    new Uint8Array([0x81]),
    u32be(GTP_F_TEID_VAL),
    new Uint8Array([10, 1, 2, 3]),
  )
  const paa = concat(new Uint8Array([1]), new Uint8Array([10, 55, 66, 77]))
  const ies = concat(v2Ie(1, imsi), v2Ie(87, fTeid), v2Ie(79, paa))
  const hdr = new Uint8Array(12)
  hdr[0] = 0x48
  hdr[1] = 32
  const msgLen = 8 + ies.length
  hdr[2] = (msgLen >> 8) & 0xff
  hdr[3] = msgLen & 0xff
  hdr[8] = 0x00
  hdr[9] = 0x01
  hdr[10] = 0x02
  hdr[11] = 0x00
  return concat(hdr, ies)
}

function buildSipOptionsForJournalCorpus(): Uint8Array {
  const body = [
    'OPTIONS sip:bob@host.example.com SIP/2.0',
    'Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKmixed',
    'From: <sip:alice@host.example.com>',
    'To: <sip:bob@host.example.com>',
    'Call-ID: t01b-mixed-options@10.0.0.2',
    'Content-Length: 0',
    '',
  ].join('\r\n')
  return new Uint8Array(Array.from(body, (c) => c.charCodeAt(0) & 0xff))
}

function buildMixedCorpusPackets(): PacketEnvelope[] {
  const frames = [
    buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, buildSipOptionsForJournalCorpus()),
    buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 53, 53, buildDnsAResponse([192, 168, 1, 50])),
    buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 54320, 3478, buildStunXorMappedIpv4([203, 0, 113, 50], 54320)),
    buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1812, 1812, buildRadiusFramedIp([192, 168, 50, 1])),
    buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], GTP_C_UDP_PORT, GTP_C_UDP_PORT, buildGtpCreateSessionRequest()),
  ]
  return frames.map((data, index) => envelope(data, index))
}

export function measureJournalOpsPacketRatio(
  journal: { readonly packets: readonly { readonly ops: readonly unknown[] }[] },
): { withOps: number; total: number; ratio: number } {
  const total = journal.packets.length
  const withOps = journal.packets.filter((p) => p.ops.length > 0).length
  return { withOps, total, ratio: total === 0 ? 0 : withOps / total }
}

export function measureLegacyResolveFreeRatio(
  discovery: {
    readonly packetDiscovery: readonly { readonly frozenPlan?: { readonly legacyResolve?: unknown } }[]
  },
): { withoutLegacy: number; total: number; ratio: number } {
  const total = discovery.packetDiscovery.length
  const withoutLegacy = discovery.packetDiscovery.filter(
    (pd) => pd.frozenPlan?.legacyResolve === undefined,
  ).length
  return { withoutLegacy, total, ratio: total === 0 ? 0 : withoutLegacy / total }
}

describe('T-01.B journal ops coverage (mixed corpus)', () => {
  it('reports share of packets with journal.ops.length>0 on SIP+DNS+STUN+RADIUS+GTP', async () => {
    const packets = buildMixedCorpusPackets()
    expect(packets).toHaveLength(T01B_MIXED_CORPUS_PACKET_COUNT)

    const fileName = 't01b-mixed-journal-ops.pcap'
    const buffer = writeClassicPcap({ header: classicHeader(1), packets })
    const session = await processCapture({
      blob: new Blob([buffer]),
      fileName,
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('high-privacy'),
      generationId: 't01b-journal-ops-gen',
      sourceId: fileName,
    })

    const measured = measureJournalOpsPacketRatio(session.journal)
    expect(measured.total).toBe(T01B_MIXED_CORPUS_PACKET_COUNT)

    // Pin ratio for ACCEPTANCE-AUDIT-LIVE-63 — update when corpus or deferredMapMeta changes.
    expect(measured.withOps).toBe(T01B_MIXED_CORPUS_PACKET_COUNT)
    expect(measured.ratio).toBe(1)

    const mapOps = session.journal.packets.flatMap((p) => p.ops).filter((o) => o.kind === 'map')
    expect(mapOps.some((o) => o.category === 'ipv4' && o.encoder === 'ipv4-octets')).toBe(true)
    expect(mapOps.some((o) => o.category === 'hostname' && o.encoder === 'fixed-ascii')).toBe(true)
    expect(mapOps.some((o) => o.category === 'teid' && o.encoder === 'u32-be')).toBe(true)

    const fpOps = session.journal.packets.flatMap((p) => p.ops).filter((o) => o.kind === 'fingerprint')
    expect(fpOps.some((o) => o.field === 'ipv4-id')).toBe(true)

    const legacyFree = measureLegacyResolveFreeRatio(session.discovery)
    expect(legacyFree.total).toBe(T01B_MIXED_CORPUS_PACKET_COUNT)
    expect(legacyFree.withoutLegacy).toBe(T01B_MIXED_CORPUS_PACKET_COUNT)
    expect(legacyFree.ratio).toBe(T01B_MIXED_CORPUS_LEGACY_RESOLVE_FREE_RATIO)
  })
})
