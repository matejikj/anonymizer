/**
 * T58 — NGAP APER over SCTP PPID 60 + typed N2 transfer adapter for T61.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { IPPROTO_SCTP } from '../../../src/pcap/protocols/types'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { sctpCrc32c, writeCrc32cLe } from '../../../src/crypto/crc32c'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import {
  encodeNgapPdu,
  encodeNgapIeValue,
  encodeN2Transfer,
  sanitizeN2Transfer,
  PPID_NGAP,
} from '../../../src/pcap/sanitize/ngap'
import {
  NGAP_IE,
  NGAP_PROC,
  NGAP_SCHEMA_MODULE,
  getAperSchema,
  APER_SCHEMA_REGISTRY,
  AMF_UE_NGAP_ID_TYPE,
  RAN_UE_NGAP_ID_TYPE,
  NGAP_NAS_PDU_TYPE,
  NGAP_CAUSE_TYPE,
  NGAP_NODE_NAME_TYPE,
  FIVE_G_S_TMSI_TYPE,
  NGAP_PINNED_IE_IDS,
  NGAP_PINNED_PROCEDURES,
  NGAP_PINNED_N2_TRANSFER_SCHEMAS,
  NGAP_FULL_TS38_413_CLAIM,
  UL_NGU_UP_TNL_TYPE,
  NGAP_TRANSPARENT_CONTAINER_TYPE,
} from '../../../src/pcap/protocols/asn1/aper'
import { encodeTbcd, TBCD_GSM } from '../../../src/pcap/protocols/application/binproto/tbcd'
import { GTP_U_UDP_PORT, teidCanonicalKey } from '../../../src/pcap/sanitize/gtp'
import { buildEthIpUdp } from '../fixtures/voipCorpus'

const IMSI_CANARY = '262011234567890'
const RAN_NAME_CANARY = 'gnb-secret-name-58'
const TEID_VAL = 0x0a1b2c3d
const UE_IP = [10, 55, 66, 77] as const

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

function buildEthIpSctp(srcIp: number[], dstIp: number[], sctpPayload: Uint8Array): Uint8Array {
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
  writeCrc32cLe(packet, 8, sctpCrc32c(packet, 0, packet.length))
}

function buildDataChunk(srcPort: number, dstPort: number, ppid: number, user: Uint8Array): Uint8Array {
  const chunkLen = 16 + user.length
  const padded = (chunkLen + 3) & ~3
  const pkt = new Uint8Array(12 + padded)
  pkt[0] = (srcPort >> 8) & 0xff
  pkt[1] = srcPort & 0xff
  pkt[2] = (dstPort >> 8) & 0xff
  pkt[3] = dstPort & 0xff
  pkt[12] = 0
  pkt[13] = 0x03
  pkt[14] = (chunkLen >> 8) & 0xff
  pkt[15] = chunkLen & 0xff
  pkt[16] = 0
  pkt[17] = 0
  pkt[18] = 0
  pkt[19] = 1
  pkt[24] = (ppid >>> 24) & 0xff
  pkt[25] = (ppid >>> 16) & 0xff
  pkt[26] = (ppid >>> 8) & 0xff
  pkt[27] = ppid & 0xff
  pkt.set(user, 28)
  finalizeSctp(pkt)
  return pkt
}

/** Minimal 5GMM Registration Request with IMSI-like mobile identity. */
function buildNasRegistration(): Uint8Array {
  const imsi = encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!
  const mi = new Uint8Array(2 + imsi.length)
  mi[0] = 1 + imsi.length
  mi[1] = 0x01 // SUCI/IMSI type nibble baseline
  mi.set(imsi, 2)
  // EPD 5GMM=0x7e, security header plain=0, msg=Registration Request 0x41
  return new Uint8Array([0x7e, 0x00, 0x41, ...mi])
}

function exportEnvelope(data: Uint8Array, index: number): PacketEnvelope {
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

function indexOfSubarray(hay: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer
    }
    return i
  }
  return -1
}

describe('T58 registry', () => {
  it('registers NGAP APER schema, mobile-core family, engine 2.36.1', () => {
    expect(APER_SCHEMA_REGISTRY.size).toBe(4)
    expect(getAperSchema(NGAP_SCHEMA_MODULE.id)?.revision).toContain('38.413')
    expect(familyForProtocol('ngap').familyId).toBe('mobile-core')
    expect(familyForProtocol('ngap-n2').familyId).toBe('mobile-core')
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
    expect(PPID_NGAP).toBe(60)
    expect(NGAP_PINNED_IE_IDS.length).toBeGreaterThanOrEqual(16)
    expect(NGAP_PINNED_PROCEDURES.length).toBeGreaterThanOrEqual(10)
    expect(NGAP_PINNED_N2_TRANSFER_SCHEMAS.length).toBe(3)
    expect(NGAP_FULL_TS38_413_CLAIM).toBe(false)
  })
})

describe('T58 InitialUEMessage + 5GS NAS', () => {
  it('maps RAN-UE-NGAP-ID; redacts IMSI via NAS child', () => {
    const nas = buildNasRegistration()
    const nasIe = encodeNgapIeValue(NGAP_NAS_PDU_TYPE, nas)
    const ranId = encodeNgapIeValue(RAN_UE_NGAP_ID_TYPE, 0x2345)
    expect(nasIe && ranId).toBeTruthy()
    const pdu = encodeNgapPdu({
      outcome: 'initiatingMessage',
      procedureCode: NGAP_PROC.INITIAL_UE_MESSAGE,
      ies: [
        { id: NGAP_IE.RAN_UE_NGAP_ID, value: ranId! },
        { id: NGAP_IE.NAS_PDU, value: nasIe! },
      ],
    })
    expect(pdu).not.toBeNull()

    const mapping = new SessionMapping(undefined, { seed: 't58-initial-ue' })
    const frame = buildEthIpSctp(
      [10, 0, 0, 1],
      [10, 0, 0, 2],
      buildDataChunk(38412, 38412, PPID_NGAP, pdu!),
    )
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(r.coverage.some((c) => c.protocol === 'ngap' || c.protocol.startsWith('ngap-'))).toBe(true)
    const out = applyPatches(frame, r)
    expect(new TextDecoder('latin1').decode(out).includes(IMSI_CANARY)).toBe(false)
    expect(indexOfSubarray(out, encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!)).toBe(-1)
    expect(mapping.map('opaque-id', 'ngap-ran-ue:9029')).not.toBe('ngap-ran-ue:9029')
  })
})

describe('T58 typed N2 transfer adapter', () => {
  it('maps TEID/UE IP via standalone schemaTypeId and nested NGAP IE (same facts)', () => {
    const transferVal = {
      pduSessionId: 5,
      ulNguUpTnl: {
        transportLayerAddress:
          (UE_IP[0]! << 24) | (UE_IP[1]! << 16) | (UE_IP[2]! << 8) | UE_IP[3]!,
        gtpTeid: new Uint8Array([
          (TEID_VAL >>> 24) & 0xff,
          (TEID_VAL >>> 16) & 0xff,
          (TEID_VAL >>> 8) & 0xff,
          TEID_VAL & 0xff,
        ]),
      },
    }
    const transfer = encodeN2Transfer('ngap.PDUSessionResourceSetupRequestTransfer', transferVal)
    expect(transfer).not.toBeNull()

    // Standalone T61 child port — not whole-NGAP-PDU guess
    const mappingStandalone = new SessionMapping(undefined, { seed: 't58-n2-standalone' })
    const collector = new PatchCollector()
    const n2 = sanitizeN2Transfer(
      'ngap.PDUSessionResourceSetupRequestTransfer',
      transfer!,
      0,
      transfer!.length,
      collector,
      mappingStandalone,
      undefined,
      0,
    )
    expect(n2?.coverage.some((c) => c.protocol === 'ngap-n2')).toBe(true)
    expect(n2?.coverage.some((c) => c.protocol.includes('PDUSessionResourceSetupRequestTransfer'))).toBe(true)
    const teidCanon = teidCanonicalKey(TEID_VAL, { receiveEndpoint: UE_IP.join('.'), plane: 'u' })
    const teidA = Number(mappingStandalone.map('teid', teidCanon)) >>> 0
    const ipA = mappingStandalone.map('ipv4', UE_IP.join('.'))
    expect(teidA).not.toBe(TEID_VAL)
    expect(teidA).not.toBe(0)
    expect(ipA).not.toBe(UE_IP.join('.'))

    // Nested: same transfer bytes as IE 74 — structured N2 path, not false whole-PDU only
    const amfId = encodeNgapIeValue(AMF_UE_NGAP_ID_TYPE, 42)
    const ranId = encodeNgapIeValue(RAN_UE_NGAP_ID_TYPE, 43)
    const pdu = encodeNgapPdu({
      outcome: 'initiatingMessage',
      procedureCode: NGAP_PROC.PDU_SESSION_RESOURCE_SETUP,
      criticality: 'reject',
      ies: [
        { id: NGAP_IE.AMF_UE_NGAP_ID, value: amfId! },
        { id: NGAP_IE.RAN_UE_NGAP_ID, value: ranId! },
        { id: NGAP_IE.PDU_SESSION_SETUP_ITEM, value: transfer! },
      ],
    })
    expect(pdu).not.toBeNull()
    const mappingNested = new SessionMapping(undefined, { seed: 't58-n2-nested' })
    const frame = buildEthIpSctp(
      [10, 0, 0, 1],
      [10, 0, 0, 2],
      buildDataChunk(38412, 38412, PPID_NGAP, pdu!),
    )
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mappingNested)
    expect(r.coverage.some((c) => c.protocol.startsWith('ngap-n2'))).toBe(true)
    const teidB = Number(mappingNested.map('teid', teidCanon)) >>> 0
    const ipB = mappingNested.map('ipv4', UE_IP.join('.'))
    expect(teidB).not.toBe(TEID_VAL)
    expect(teidB).not.toBe(0)
    expect(ipB).not.toBe(UE_IP.join('.'))
    const out = applyPatches(frame, r)
    const teidWire = new Uint8Array([
      (TEID_VAL >>> 24) & 0xff,
      (TEID_VAL >>> 16) & 0xff,
      (TEID_VAL >>> 8) & 0xff,
      TEID_VAL & 0xff,
    ])
    expect(indexOfSubarray(out, teidWire)).toBe(-1)
    expect(indexOfSubarray(out, new Uint8Array(UE_IP))).toBe(-1)
  })
})

describe('R07 N2 transfer ↔ GTP-U TEID namespace', () => {
  const GTP_RECEIVE = [10, 1, 2, 3] as const

  function buildGtpU(teid: number, tpdu: Uint8Array): Uint8Array {
    const hdr = new Uint8Array(8)
    hdr[0] = 0x30
    hdr[1] = 0xff
    hdr[2] = (tpdu.length >> 8) & 0xff
    hdr[3] = tpdu.length & 0xff
    hdr[4] = (teid >>> 24) & 0xff
    hdr[5] = (teid >>> 16) & 0xff
    hdr[6] = (teid >>> 8) & 0xff
    hdr[7] = teid & 0xff
    const out = new Uint8Array(hdr.length + tpdu.length)
    out.set(hdr, 0)
    out.set(tpdu, hdr.length)
    return out
  }

  function readTeidBe(buf: Uint8Array, off: number): number {
    return ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0
  }

  it('maps identical wire TEID for same receive endpoint under one SessionMapping', () => {
    const mapping = new SessionMapping(undefined, { seed: 'r07-n2-gtpu-teid' })
    const teidCanon = teidCanonicalKey(TEID_VAL, {
      receiveEndpoint: GTP_RECEIVE.join('.'),
      plane: 'u',
    })

    const transferVal = {
      pduSessionId: 5,
      ulNguUpTnl: {
        transportLayerAddress:
          (GTP_RECEIVE[0]! << 24)
          | (GTP_RECEIVE[1]! << 16)
          | (GTP_RECEIVE[2]! << 8)
          | GTP_RECEIVE[3]!,
        gtpTeid: new Uint8Array([
          (TEID_VAL >>> 24) & 0xff,
          (TEID_VAL >>> 16) & 0xff,
          (TEID_VAL >>> 8) & 0xff,
          TEID_VAL & 0xff,
        ]),
      },
    }
    const transfer = encodeN2Transfer('ngap.PDUSessionResourceSetupRequestTransfer', transferVal)
    expect(transfer).not.toBeNull()

    const collector = new PatchCollector(transfer!.length)
    const n2 = sanitizeN2Transfer(
      'ngap.PDUSessionResourceSetupRequestTransfer',
      transfer!,
      0,
      transfer!.length,
      collector,
      mapping,
      undefined,
      0,
    )
    expect(n2?.coverage.some((c) => c.protocol === 'ngap-n2')).toBe(true)
    const n2Out = transfer!.slice()
    collector.resolveDeferred({ mapping })
    for (const p of collector.getPatches()) n2Out.set(p.data, p.offset)
    const n2TeidOff = indexOfSubarray(transfer!, new Uint8Array([
      (TEID_VAL >>> 24) & 0xff,
      (TEID_VAL >>> 16) & 0xff,
      (TEID_VAL >>> 8) & 0xff,
      TEID_VAL & 0xff,
    ]))
    expect(n2TeidOff).toBeGreaterThanOrEqual(0)
    const n2TeidWire = readTeidBe(n2Out, n2TeidOff)

    const tpdu = new Uint8Array([0x45, 0, 0, 0x14, 0, 0, 0, 0, 64, 0x11, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2])
    const gtpU = buildGtpU(TEID_VAL, tpdu)
    const frameU = buildEthIpUdp(
      [10, 1, 2, 4],
      [...GTP_RECEIVE],
      GTP_U_UDP_PORT,
      GTP_U_UDP_PORT,
      gtpU,
    )
    const rU = sanitizePacket(packetInput(frameU), DIAGNOSTIC_POLICY, mapping)
    expect(rU.coverage.some((c) => c.protocol === 'gtp-u')).toBe(true)
    const outU = applyPatches(frameU, rU)
    const gtpPayloadOff = 14 + 20 + 8
    const gtpuTeidWire = readTeidBe(outU, gtpPayloadOff + 4)

    const expectedAlias = Number(mapping.map('teid', teidCanon)) >>> 0
    expect(n2TeidWire).toBe(expectedAlias)
    expect(gtpuTeidWire).toBe(expectedAlias)
    expect(n2TeidWire).toBe(gtpuTeidWire)
    expect(n2TeidWire).not.toBe(TEID_VAL)
  })
})

describe('T58 UL-NGU + handover', () => {
  it('maps UL NG-U TEID/IPv4 and masks transparent container', () => {
    const teid = new Uint8Array([
      (TEID_VAL >>> 24) & 0xff,
      (TEID_VAL >>> 16) & 0xff,
      (TEID_VAL >>> 8) & 0xff,
      TEID_VAL & 0xff,
    ])
    const ulTnl = encodeNgapIeValue(UL_NGU_UP_TNL_TYPE, {
      transportLayerAddress:
        (UE_IP[0]! << 24) | (UE_IP[1]! << 16) | (UE_IP[2]! << 8) | UE_IP[3]!,
      gtpTeid: teid,
    })
    const rrcCanary = new Uint8Array([0xde, 0xad, 0xca, 0xfe, 0x01, 0x02])
    const handover = encodeNgapIeValue(NGAP_TRANSPARENT_CONTAINER_TYPE, rrcCanary)
    const ranId = encodeNgapIeValue(RAN_UE_NGAP_ID_TYPE, 1)
    const amfId = encodeNgapIeValue(AMF_UE_NGAP_ID_TYPE, 2)
    const pdu = encodeNgapPdu({
      outcome: 'initiatingMessage',
      procedureCode: NGAP_PROC.HANDOVER_PREPARATION,
      ies: [
        { id: NGAP_IE.AMF_UE_NGAP_ID, value: amfId! },
        { id: NGAP_IE.RAN_UE_NGAP_ID, value: ranId! },
        { id: NGAP_IE.UL_NGU_UP_TNL, value: ulTnl! },
        { id: NGAP_IE.SOURCE_TO_TARGET_TRANSPARENT_CONTAINER, value: handover! },
      ],
    })
    expect(pdu).not.toBeNull()
    const mapping = new SessionMapping(undefined, { seed: 't58-ul-ngu-ho' })
    const frame = buildEthIpSctp(
      [10, 0, 0, 1],
      [10, 0, 0, 2],
      buildDataChunk(38412, 38412, PPID_NGAP, pdu!),
    )
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(r.coverage.some((c) => c.protocol === 'ngap-ngu-tunnel')).toBe(true)
    expect(r.coverage.some((c) => c.protocol === 'ngap-transparent-container')).toBe(true)
    expect(indexOfSubarray(out, teid)).toBe(-1)
    expect(indexOfSubarray(out, rrcCanary)).toBe(-1)
  })
})

describe('T58 export pipeline', () => {
  it('diagnostic export keeps one SCTP frame and redacts NAS canary', () => {
    const nas = buildNasRegistration()
    const nasIe = encodeNgapIeValue(NGAP_NAS_PDU_TYPE, nas)
    const ranId = encodeNgapIeValue(RAN_UE_NGAP_ID_TYPE, 9)
    const pdu = encodeNgapPdu({
      outcome: 'initiatingMessage',
      procedureCode: NGAP_PROC.INITIAL_UE_MESSAGE,
      ies: [
        { id: NGAP_IE.RAN_UE_NGAP_ID, value: ranId! },
        { id: NGAP_IE.NAS_PDU, value: nasIe! },
      ],
    })!
    const frame = buildEthIpSctp(
      [10, 0, 0, 1],
      [10, 0, 0, 2],
      buildDataChunk(38412, 38412, PPID_NGAP, pdu),
    )
    const { built } = runExportPipeline(
      [exportEnvelope(frame, 0)],
      'diagnostic',
      't58-export.pcap',
      't58-export',
      { mappingSeed: 't58-export-seed' },
    )
    expect(built.packets.length).toBe(1)
    expect(new TextDecoder('latin1').decode(built.packets[0]!.data).includes(IMSI_CANARY)).toBe(false)
  })
})

describe('T58 NGSetup + secrets', () => {
  it('maps RAN node name; masks SecurityKey and FiveG-S-TMSI; preserves Cause', () => {
    const nameIe = encodeNgapIeValue(NGAP_NODE_NAME_TYPE, new TextEncoder().encode(RAN_NAME_CANARY))
    const key = new Uint8Array(32)
    key[0] = 0xde
    key[1] = 0xad
    key[2] = 0xbe
    key[3] = 0xef
    const stmsi = encodeNgapIeValue(FIVE_G_S_TMSI_TYPE, new Uint8Array([1, 2, 3, 4, 5, 6]))
    const cause = encodeNgapIeValue(NGAP_CAUSE_TYPE, { alt: 'nas', value: 'normal-release' })
    const pdu = encodeNgapPdu({
      outcome: 'initiatingMessage',
      procedureCode: NGAP_PROC.NG_SETUP,
      ies: [
        { id: NGAP_IE.RAN_NODE_NAME, value: nameIe! },
        { id: NGAP_IE.SECURITY_KEY, value: key },
        { id: NGAP_IE.FIVE_G_S_TMSI, value: stmsi! },
        { id: NGAP_IE.CAUSE, value: cause! },
        { id: 9999, value: new Uint8Array([0xca, 0xfe, 0x00, 0x01]) },
      ],
    })
    expect(pdu).not.toBeNull()
    const mapping = new SessionMapping(undefined, { seed: 't58-ngsetup' })
    const frame = buildEthIpSctp(
      [10, 0, 0, 1],
      [10, 0, 0, 2],
      buildDataChunk(38412, 38412, PPID_NGAP, pdu!),
    )
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(new TextDecoder('latin1').decode(out).includes(RAN_NAME_CANARY)).toBe(false)
    expect(indexOfSubarray(out, new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe(-1)
    expect(indexOfSubarray(out, new Uint8Array([0xca, 0xfe, 0x00, 0x01]))).toBe(-1)
    expect(r.coverage.some((c) => c.protocol === 'ngap-security-key')).toBe(true)
    expect(r.coverage.some((c) => c.protocol === 'ngap-cause')).toBe(true)
    expect(r.coverage.some((c) => c.protocol === 'ngap-node-name')).toBe(true)
  })
})
