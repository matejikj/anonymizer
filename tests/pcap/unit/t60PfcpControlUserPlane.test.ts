/**
 * T60 — PFCP Sx/N4 canaries (SEID, F-TEID, UE IP, User ID, SDF mask, GTP TEID reuse).
 */
import { describe, expect, it } from 'vitest'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { runDiagnosticExportPipeline } from '../helpers/diagnosticPipeline'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { encodeTbcd, TBCD_GSM } from '../../../src/pcap/protocols/application/binproto/tbcd'
import {
  PFCP_UDP_PORT,
  encodeSeidWireAlias,
  seidMappingCanonical,
} from '../../../src/pcap/sanitize/pfcp'
import { disposeProtocolGraphStateForSession } from '../../../src/pcap/sanitize/protocolGraphState'
import { GTP_U_UDP_PORT, teidCanonicalKey } from '../../../src/pcap/sanitize/gtp'

const IMSI_CANARY = '262011234567890'
const UE_IP = [10, 55, 66, 77] as const
const F_TEID_VAL = 0x0a1b2c3d
const SEID_HEX = '0123456789abcdef'
const SDF_CANARY = 'permit out ip from 10.55.66.77 to any'

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

function u16be(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff])
}

function u32be(n: number): Uint8Array {
  return new Uint8Array([
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ])
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

function ie(type: number, value: Uint8Array): Uint8Array {
  return concat(u16be(type), u16be(value.length), value)
}

function seidBytes(): Uint8Array {
  const out = new Uint8Array(8)
  for (let i = 0; i < 8; i++) {
    out[i] = parseInt(SEID_HEX.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

/** Association Setup Request: Node ID IPv4 + Recovery Time Stamp. */
function buildAssociationSetup(nodeIpv4: readonly number[] = [10, 1, 2, 3]): Uint8Array {
  const nodeId = concat(new Uint8Array([0x00]), new Uint8Array(nodeIpv4))
  const recovery = u32be(0xe0000001) // NTP-ish non-zero
  const body = concat(ie(60, nodeId), ie(96, recovery))
  // Node message: S=0, msg=5, length = seq(4) + body
  const msgLen = 4 + body.length
  const hdr = new Uint8Array(8)
  hdr[0] = 0x20 // ver=1, S=0
  hdr[1] = 5 // Association Setup Request
  hdr[2] = (msgLen >> 8) & 0xff
  hdr[3] = msgLen & 0xff
  hdr[4] = 0x00
  hdr[5] = 0x00
  hdr[6] = 0x01 // seq
  hdr[7] = 0x00
  return concat(hdr, body)
}

/** Session Establishment Request with CP F-SEID, Create PDR (F-TEID + UE IP + SDF), User ID. */
function buildSessionEstablishment(): Uint8Array {
  const fseid = concat(
    new Uint8Array([0x02]), // V4=1 (bit2)
    seidBytes(),
    new Uint8Array([10, 2, 3, 4]),
  )
  const fteid = concat(
    new Uint8Array([0x01]), // V4
    u32be(F_TEID_VAL),
    new Uint8Array([10, 1, 2, 3]),
  )
  const ueIp = concat(new Uint8Array([0x02]), new Uint8Array(UE_IP)) // V4
  const sdfFlags = new Uint8Array([0x01]) // FD
  const sdfDesc = new TextEncoder().encode(SDF_CANARY)
  const sdf = concat(sdfFlags, u16be(sdfDesc.length), sdfDesc)
  const pdi = concat(ie(21, fteid), ie(93, ueIp), ie(23, sdf))
  const createPdr = concat(ie(56, u16be(1)), ie(2, pdi)) // PDR ID + PDI
  const imsi = encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!
  const userId = concat(
    new Uint8Array([0x01]), // IMSIF
    new Uint8Array([imsi.length]),
    imsi,
  )
  const body = concat(ie(57, fseid), ie(1, createPdr), ie(141, userId), ie(19, new Uint8Array([1])))
  const seid = seidBytes()
  const msgLen = 8 + 4 + body.length // SEID(8)+seq(4)+body — length after first 4
  const hdr = new Uint8Array(16)
  hdr[0] = 0x21 // ver=1, S=1
  hdr[1] = 50 // Session Establishment Request
  hdr[2] = (msgLen >> 8) & 0xff
  hdr[3] = msgLen & 0xff
  hdr.set(seid, 4)
  hdr[12] = 0x00
  hdr[13] = 0x00
  hdr[14] = 0x02
  hdr[15] = 0x00
  return concat(hdr, body)
}

function buildSessionMessage(msgType: number, seq: number, body: Uint8Array): Uint8Array {
  const seid = seidBytes()
  const msgLen = 8 + 4 + body.length
  const hdr = new Uint8Array(16)
  hdr[0] = 0x21
  hdr[1] = msgType
  hdr[2] = (msgLen >> 8) & 0xff
  hdr[3] = msgLen & 0xff
  hdr.set(seid, 4)
  hdr[12] = 0x00
  hdr[13] = 0x00
  hdr[14] = seq & 0xff
  hdr[15] = (seq >> 8) & 0xff
  return concat(hdr, body)
}

/** Session Modification: Update FAR → Forwarding Parameters → OHC (scoped TEID). */
function buildSessionModification(): Uint8Array {
  const ohcTeid = 0x55667788
  const ohc = ie(
    84,
    concat(u16be(0x0001), u32be(ohcTeid), new Uint8Array([10, 1, 2, 3])),
  )
  const fwd = ie(4, ohc)
  const updateFar = ie(10, concat(ie(108, u16be(1)), fwd))
  return buildSessionMessage(51, 3, updateFar)
}

function buildSessionDeletion(): Uint8Array {
  return buildSessionMessage(52, 4, ie(19, new Uint8Array([1])))
}

function pfcpFrame(msg: Uint8Array): Uint8Array {
  return buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], PFCP_UDP_PORT, PFCP_UDP_PORT, msg)
}

function packetEnvelope(data: Uint8Array, index = 0): PacketEnvelope {
  return {
    packetNumber: index,
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
    fileOffset: 24,
    data,
  }
}

function buildGtpU(teid: number, tpdu: Uint8Array): Uint8Array {
  const hdr = new Uint8Array(8)
  hdr[0] = 0x30
  hdr[1] = 0xff
  hdr[2] = (tpdu.length >> 8) & 0xff
  hdr[3] = tpdu.length & 0xff
  hdr.set(u32be(teid), 4)
  return concat(hdr, tpdu)
}

function indexOfSubarray(hay: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer
    }
    return i
  }
  return -1
}

describe('T60 registry', () => {
  it('registers pfcp handler, mobile-core family, engine 2.35.0', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('pfcp')
    expect(familyForProtocol('pfcp').familyId).toBe('mobile-core')
    expect(familyForProtocol('pfcp-f-seid').familyId).toBe('mobile-core')
    expect(PCAP_ENGINE_VERSION).toBe('2.35.0')
  })
})

describe('T60 Association Setup', () => {
  it('maps Node ID IPv4; does not claim GTP-U port as PFCP', () => {
    const mapping = new SessionMapping(undefined, { seed: 't60-assoc' })
    const msg = buildAssociationSetup()
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], PFCP_UDP_PORT, PFCP_UDP_PORT, msg)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(r.coverage.some((c) => c.protocol === 'pfcp' || c.protocol === 'pfcp-node-id')).toBe(true)
    const out = applyPatches(frame, r)
    const nodeAlias = mapping.map('ipv4', '10.1.2.3')
    expect(nodeAlias).not.toBe('10.1.2.3')
    // Wire should not keep original node IP bytes
    expect(indexOfSubarray(out, new Uint8Array([10, 1, 2, 3]))).toBe(-1)

    // GTP-U port must not be claimed by PFCP even with similar version nibble
    const gtpLike = new Uint8Array(16)
    gtpLike[0] = 0x30
    gtpLike[1] = 0xff
    const gtpFrame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], GTP_U_UDP_PORT, GTP_U_UDP_PORT, gtpLike)
    const rG = sanitizePacket(packetInput(gtpFrame), DIAGNOSTIC_POLICY, mapping)
    expect(rG.coverage.some((c) => c.protocol.startsWith('pfcp'))).toBe(false)
  })
})

describe('T60 Session Establishment + GTP-U TEID', () => {
  it('maps SEID≠TEID, F-TEID, UE IP, IMSI; masks SDF canary; TEID matches GTP-U', () => {
    const mapping = new SessionMapping(undefined, { seed: 't60-session' })
    const msg = buildSessionEstablishment()
    const frame = buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], PFCP_UDP_PORT, PFCP_UDP_PORT, msg)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(r.coverage.some((c) => c.protocol === 'pfcp')).toBe(true)
    const out = applyPatches(frame, r)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes(SDF_CANARY)).toBe(false)
    expect(text.includes(IMSI_CANARY)).toBe(false)
    const imsiWire = encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!
    expect(indexOfSubarray(out, imsiWire)).toBe(-1)
    expect(indexOfSubarray(out, seidBytes())).toBe(-1)

    const teidCanon = teidCanonicalKey(F_TEID_VAL, { receiveEndpoint: '10.1.2.3', plane: 'u' })
    const teidAlias = Number(mapping.map('teid', teidCanon)) >>> 0
    expect(teidAlias).not.toBe(F_TEID_VAL)
    expect(teidAlias).not.toBe(0)

    const ueAlias = mapping.map('ipv4', UE_IP.join('.'))
    expect(ueAlias).not.toBe(UE_IP.join('.'))

    // SEID uses opaque-id, not teid category
    const seidCanon = seidMappingCanonical(SEID_HEX, {
      receiveEndpoint: '10.0.0.20',
      role: 'cp',
      generation: 1,
    })
    const seidAlias = mapping.map('opaque-id', seidCanon)
    expect(seidAlias).not.toBe(seidCanon)
    expect(mapping.map('teid', teidCanon)).not.toBe(seidAlias)

    const tpdu = new Uint8Array([0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 1, 0, 0, ...UE_IP, 10, 0, 0, 1])
    const gtpU = buildGtpU(F_TEID_VAL, tpdu)
    // Outer dst = F-TEID receive endpoint so header TEID shares the scoped alias.
    const frameU = buildEthIpUdp([10, 1, 2, 4], [10, 1, 2, 3], GTP_U_UDP_PORT, GTP_U_UDP_PORT, gtpU)
    const rU = sanitizePacket(packetInput(frameU), DIAGNOSTIC_POLICY, mapping)
    const outU = applyPatches(frameU, rU)
    const gtpPayloadOff = 14 + 20 + 8
    const teidOut =
      ((outU[gtpPayloadOff + 4]! << 24)
        | (outU[gtpPayloadOff + 5]! << 16)
        | (outU[gtpPayloadOff + 6]! << 8)
        | outU[gtpPayloadOff + 7]!) >>> 0
    expect(teidOut).toBe(teidAlias)
  })
})

describe('T60 SEID wire stability (V13)', () => {
  it('same SEID yields identical wire bytes across offsets and packets', () => {
    const mapping = new SessionMapping(undefined, { seed: 't60-seid-stable' })
    const msg = buildSessionEstablishment()
    const frame = buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], PFCP_UDP_PORT, PFCP_UDP_PORT, msg)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    const udpOff = 14 + 20 + 8
    const hdrSeid = out.subarray(udpOff + 4, udpOff + 12)
    expect(indexOfSubarray(out, seidBytes())).toBe(-1)
    const alias = mapping.map(
      'opaque-id',
      seidMappingCanonical(SEID_HEX, { receiveEndpoint: '10.0.0.20', role: 'cp', generation: 1 }),
    )
    const expected = encodeSeidWireAlias(alias)
    expect([...hdrSeid]).toEqual([...expected])
    // Encoder itself is offset-independent
    expect([...encodeSeidWireAlias(alias)]).toEqual([...encodeSeidWireAlias(alias)])
    // F-SEID carries the same 8 bytes somewhere in the payload
    expect(indexOfSubarray(out, expected)).toBeGreaterThanOrEqual(0)
    // Count occurrences: header + F-SEID (≥2)
    let hits = 0
    let searchFrom = 0
    while (searchFrom <= out.length - 8) {
      const at = indexOfSubarray(out.subarray(searchFrom), expected)
      if (at < 0) break
      hits++
      searchFrom += at + 1
    }
    expect(hits).toBeGreaterThanOrEqual(2)
    const r2 = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out2 = applyPatches(frame, r2)
    expect([...out2.subarray(udpOff + 4, udpOff + 12)]).toEqual([...hdrSeid])
  })
})

describe('T60 Outer Header Creation TEID scope', () => {
  it('masks OHC TEID when outer IP is absent (no shared fake receiveEndpoint)', () => {
    const mapping = new SessionMapping(undefined, { seed: 't60-ohc' })
    // Description bit0 = GTP-U/UDP/IPv4, but value carries only TEID (no IPv4) → unscoped.
    const teid = u32be(0x0a1b2c3d)
    const ohc = ie(84, concat(u16be(0x0001), teid))
    const msgLen = 4 + ohc.length
    const hdr = new Uint8Array(8)
    hdr[0] = 0x20
    hdr[1] = 1
    hdr[2] = (msgLen >> 8) & 0xff
    hdr[3] = msgLen & 0xff
    const msg = concat(hdr, ohc)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], PFCP_UDP_PORT, PFCP_UDP_PORT, msg)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(indexOfSubarray(out, teid)).toBe(-1)
    // Must not register a TEID alias under a fake shared endpoint.
    expect(
      mapping.get('teid', teidCanonicalKey(0x0a1b2c3d, { receiveEndpoint: 'pfcp-ohc', plane: 'u' })),
    ).toBeUndefined()
    expect(r.coverage.some((c) => c.protocol === 'pfcp-ohc')).toBe(true)
  })

  it('scopes OHC TEID to outer IPv4 when present', () => {
    const mapping = new SessionMapping(undefined, { seed: 't60-ohc-ip' })
    const teid = u32be(0x11223344)
    const ohc = ie(84, concat(u16be(0x0001), teid, new Uint8Array([203, 0, 113, 10])))
    const msgLen = 4 + ohc.length
    const hdr = new Uint8Array(8)
    hdr[0] = 0x20
    hdr[1] = 1
    hdr[2] = (msgLen >> 8) & 0xff
    hdr[3] = msgLen & 0xff
    const msg = concat(hdr, ohc)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], PFCP_UDP_PORT, PFCP_UDP_PORT, msg)
    sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(
      mapping.get('teid', teidCanonicalKey(0x11223344, { receiveEndpoint: '203.0.113.10', plane: 'u' })),
    ).toBeDefined()
  })
})

describe('T60 session lifecycle (SEID / F-TEID / OHC / GTP-U)', () => {
  it('create→modify→delete keeps header SEID wire alias stable', () => {
    const mapping = new SessionMapping(undefined, { seed: 't60-lifecycle' })
    const frames = [
      pfcpFrame(buildSessionEstablishment()),
      pfcpFrame(buildSessionModification()),
      pfcpFrame(buildSessionDeletion()),
    ]
    const hdrSeids: Uint8Array[] = []
    for (let i = 0; i < frames.length; i++) {
      const r = sanitizePacket(packetInput(frames[i]!, i), DIAGNOSTIC_POLICY, mapping)
      expect(r.coverage.some((c) => c.protocol === 'pfcp')).toBe(true)
      const out = applyPatches(frames[i]!, r)
      const udpOff = 14 + 20 + 8
      hdrSeids.push(out.subarray(udpOff + 4, udpOff + 12))
    }
    expect([...hdrSeids[0]!]).toEqual([...hdrSeids[1]!])
    expect([...hdrSeids[1]!]).toEqual([...hdrSeids[2]!])
    expect(indexOfSubarray(hdrSeids[0]!, seidBytes())).toBe(-1)
  })

  it('modification OHC TEID scopes to GTP-U on the same mapping', () => {
    const mapping = new SessionMapping(undefined, { seed: 't60-lifecycle-gtpu' })
    sanitizePacket(packetInput(pfcpFrame(buildSessionEstablishment()), 0), DIAGNOSTIC_POLICY, mapping)
    sanitizePacket(packetInput(pfcpFrame(buildSessionModification()), 1), DIAGNOSTIC_POLICY, mapping)
    const ohcCanon = teidCanonicalKey(0x55667788, { receiveEndpoint: '10.1.2.3', plane: 'u' })
    const ohcAlias = Number(mapping.map('teid', ohcCanon)) >>> 0
    const tpdu = new Uint8Array([0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 1, 0, 0, ...UE_IP, 10, 0, 0, 1])
    const gtpU = buildGtpU(0x55667788, tpdu)
    const frameU = buildEthIpUdp([10, 1, 2, 4], [10, 1, 2, 3], GTP_U_UDP_PORT, GTP_U_UDP_PORT, gtpU)
    const rU = sanitizePacket(packetInput(frameU, 2), DIAGNOSTIC_POLICY, mapping)
    const outU = applyPatches(frameU, rU)
    const gtpPayloadOff = 14 + 20 + 8
    const teidOut =
      ((outU[gtpPayloadOff + 4]! << 24)
        | (outU[gtpPayloadOff + 5]! << 16)
        | (outU[gtpPayloadOff + 6]! << 8)
        | outU[gtpPayloadOff + 7]!) >>> 0
    expect(teidOut).toBe(ohcAlias)
  })

  it('multi-session export: two SEIDs and dispose do not cross-scope TEIDs', () => {
    disposeProtocolGraphStateForSession()
    const seidB = new Uint8Array(8)
    for (let i = 0; i < 8; i++) seidB[i] = 0xab
    const fteidB = concat(new Uint8Array([0x01]), u32be(F_TEID_VAL), new Uint8Array([10, 9, 9, 9]))
    const pdiB = concat(ie(21, fteidB), ie(93, concat(new Uint8Array([0x02]), new Uint8Array([10, 8, 8, 8]))))
    const createPdrB = concat(ie(56, u16be(2)), ie(2, pdiB))
    const fseidB = concat(new Uint8Array([0x02]), seidB, new Uint8Array([10, 2, 3, 5]))
    const bodyB = concat(ie(57, fseidB), ie(1, createPdrB))
    const msgLenB = 8 + 4 + bodyB.length
    const hdrB = new Uint8Array(16)
    hdrB[0] = 0x21
    hdrB[1] = 50
    hdrB[2] = (msgLenB >> 8) & 0xff
    hdrB[3] = msgLenB & 0xff
    hdrB.set(seidB, 4)
    hdrB[14] = 0x05
    const establishB = concat(hdrB, bodyB)

    const packets = [
      packetEnvelope(pfcpFrame(buildSessionEstablishment()), 0),
      packetEnvelope(pfcpFrame(buildSessionModification()), 1),
      packetEnvelope(pfcpFrame(buildSessionDeletion()), 2),
      packetEnvelope(pfcpFrame(establishB), 3),
    ]
    const { built, discovery } = runDiagnosticExportPipeline(
      packets,
      't60-lifecycle.pcap',
      't60-lifecycle',
      { mappingSeed: 't60-lifecycle-export' },
    )
    expect(built.validationValid).toBe(true)
    expect(discovery.packetDiscovery.some((p) => p.coverage.some((c) => c.protocol === 'pfcp-f-teid'))).toBe(
      true,
    )
    const exported = built.packets.map((p) => p.data)
    const latin1 = exported.map((d) => new TextDecoder('latin1').decode(d))
    expect(latin1.every((t) => !t.includes(SDF_CANARY) && !t.includes(IMSI_CANARY))).toBe(true)
    expect(exported.every((d) => indexOfSubarray(d, seidBytes()) === -1)).toBe(true)
    expect(exported.every((d) => indexOfSubarray(d, seidB) === -1)).toBe(true)

    const scopeA = teidCanonicalKey(F_TEID_VAL, { receiveEndpoint: '10.1.2.3', plane: 'u' })
    const scopeB = teidCanonicalKey(F_TEID_VAL, { receiveEndpoint: '10.9.9.9', plane: 'u' })
    const mapping = new SessionMapping(undefined, { seed: 't60-lifecycle-export' })
    sanitizePacket(packetInput(pfcpFrame(buildSessionEstablishment()), 0), DIAGNOSTIC_POLICY, mapping)
    sanitizePacket(packetInput(pfcpFrame(establishB), 1), DIAGNOSTIC_POLICY, mapping)
    expect(mapping.map('teid', scopeA)).not.toBe(mapping.map('teid', scopeB))
  })
})

describe('T60 F-SEID session scope (CP/UP, endpoint, generation)', () => {
  const RECEIVER_A = '10.0.0.20'

  it('CP and UP roles with the same SEID hex use distinct mapping canonicals', () => {
    const cp = seidMappingCanonical(SEID_HEX, { receiveEndpoint: RECEIVER_A, role: 'cp', generation: 1 })
    const up = seidMappingCanonical(SEID_HEX, { receiveEndpoint: RECEIVER_A, role: 'up', generation: 1 })
    expect(cp).not.toBe(up)
  })

  it('export: same SEID hex on two receive endpoints yields different header aliases', () => {
    disposeProtocolGraphStateForSession()
    const msg = buildSessionEstablishment()
    const frameA = buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], PFCP_UDP_PORT, PFCP_UDP_PORT, msg)
    const frameB = buildEthIpUdp([10, 0, 0, 30], [10, 0, 0, 40], PFCP_UDP_PORT, PFCP_UDP_PORT, msg)
    const { built } = runDiagnosticExportPipeline(
      [packetEnvelope(frameA, 0), packetEnvelope(frameB, 1)],
      't60-seid-endpoint.pcap',
      't60-seid-endpoint',
      { mappingSeed: 't60-seid-endpoint-export' },
    )
    expect(built.validationValid).toBe(true)
    const udpOff = 14 + 20 + 8
    const aliasA = built.packets[0]!.data.subarray(udpOff + 4, udpOff + 12)
    const aliasB = built.packets[1]!.data.subarray(udpOff + 4, udpOff + 12)
    expect([...aliasA]).not.toEqual([...aliasB])
    expect(indexOfSubarray(built.packets[0]!.data, seidBytes())).toBe(-1)
    expect(indexOfSubarray(built.packets[1]!.data, seidBytes())).toBe(-1)
  })

  it('delete then re-establish assigns a new generation alias on the same transport', () => {
    const mapping = new SessionMapping(undefined, { seed: 't60-regen' })
    const frames = [
      pfcpFrame(buildSessionEstablishment()),
      pfcpFrame(buildSessionDeletion()),
      pfcpFrame(buildSessionEstablishment()),
    ]
    const udpOff = 14 + 20 + 8
    const hdrAliases: Uint8Array[] = []
    for (let i = 0; i < frames.length; i++) {
      const r = sanitizePacket(packetInput(frames[i]!, i), DIAGNOSTIC_POLICY, mapping)
      hdrAliases.push(applyPatches(frames[i]!, r).subarray(udpOff + 4, udpOff + 12))
    }
    expect([...hdrAliases[0]!]).toEqual([...hdrAliases[1]!])
    expect([...hdrAliases[2]!]).not.toEqual([...hdrAliases[0]!])
    const gen1 = seidMappingCanonical(SEID_HEX, { receiveEndpoint: RECEIVER_A, role: 'cp', generation: 1 })
    const gen2 = seidMappingCanonical(SEID_HEX, { receiveEndpoint: RECEIVER_A, role: 'cp', generation: 2 })
    expect(mapping.map('opaque-id', gen1)).not.toBe(mapping.map('opaque-id', gen2))
  })

  it('dispose resets graph state for a subsequent mapping session', () => {
    const mapping = new SessionMapping(undefined, { seed: 't60-dispose' })
    sanitizePacket(packetInput(pfcpFrame(buildSessionEstablishment())), DIAGNOSTIC_POLICY, mapping)
    const before = mapping.map(
      'opaque-id',
      seidMappingCanonical(SEID_HEX, { receiveEndpoint: RECEIVER_A, role: 'cp', generation: 1 }),
    )
    disposeProtocolGraphStateForSession()
    sanitizePacket(packetInput(pfcpFrame(buildSessionEstablishment())), DIAGNOSTIC_POLICY, mapping)
    const after = mapping.map(
      'opaque-id',
      seidMappingCanonical(SEID_HEX, { receiveEndpoint: RECEIVER_A, role: 'cp', generation: 1 }),
    )
    expect(after).toBe(before)
  })

  it('SMF failover (new Association Node ID) does not reuse prior SEID aliases', () => {
    disposeProtocolGraphStateForSession()
    const mapping = new SessionMapping(undefined, { seed: 't60-failover' })
    const udpOff = 14 + 20 + 8
    sanitizePacket(packetInput(pfcpFrame(buildAssociationSetup([10, 1, 2, 3]))), DIAGNOSTIC_POLICY, mapping)
    const frame1 = pfcpFrame(buildSessionEstablishment())
    const r1 = sanitizePacket(packetInput(frame1), DIAGNOSTIC_POLICY, mapping)
    const alias1 = applyPatches(frame1, r1).subarray(udpOff + 4, udpOff + 12)
    // New SMF Node ID on the same UDP transport — unrelated control plane.
    sanitizePacket(packetInput(pfcpFrame(buildAssociationSetup([10, 9, 9, 9]))), DIAGNOSTIC_POLICY, mapping)
    const frame2 = pfcpFrame(buildSessionEstablishment())
    const r2 = sanitizePacket(packetInput(frame2), DIAGNOSTIC_POLICY, mapping)
    const alias2 = applyPatches(frame2, r2).subarray(udpOff + 4, udpOff + 12)
    expect([...alias1]).not.toEqual([...alias2])
    const e0 = seidMappingCanonical(SEID_HEX, {
      receiveEndpoint: RECEIVER_A,
      role: 'cp',
      generation: 1,
      associationEpoch: 0,
    })
    const e1 = seidMappingCanonical(SEID_HEX, {
      receiveEndpoint: RECEIVER_A,
      role: 'cp',
      generation: 2,
      associationEpoch: 1,
    })
    expect(mapping.map('opaque-id', e0)).not.toBe(mapping.map('opaque-id', e1))
  })
})

describe('T60 enterprise unknown IE', () => {
  it('masks enterprise IE value while preserving type/length/vendor framing', () => {
    const mapping = new SessionMapping(undefined, { seed: 't60-ent' })
    const secret = new TextEncoder().encode('ENT-SECRET-CANARY')
    const entValue = concat(u32be(0x1234), secret) // vendor + payload
    const body = ie(0x8001, entValue)
    const msgLen = 4 + body.length
    const hdr = new Uint8Array(8)
    hdr[0] = 0x20
    hdr[1] = 1 // Heartbeat Request
    hdr[2] = (msgLen >> 8) & 0xff
    hdr[3] = msgLen & 0xff
    const msg = concat(hdr, body)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], PFCP_UDP_PORT, PFCP_UDP_PORT, msg)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(new TextDecoder('latin1').decode(out).includes('ENT-SECRET-CANARY')).toBe(false)
    expect(r.coverage.some((c) => c.protocol === 'pfcp-enterprise')).toBe(true)
  })
})
