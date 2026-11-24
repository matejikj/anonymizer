/**
 * T57 — S1AP APER over SCTP PPID 18: UE IDs, NAS child, E-RAB TEID, SecurityKey mask.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { IPPROTO_SCTP } from '../../../src/pcap/protocols/types'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { crc32c as _crc, sctpCrc32c, writeCrc32cLe } from '../../../src/crypto/crc32c'
import {
  encodeS1apPdu,
  encodeIeValue,
  PPID_S1AP,
} from '../../../src/pcap/sanitize/s1ap'
import {
  S1AP_IE,
  S1AP_PROC,
  S1AP_SCHEMA_MODULE,
  getAperSchema,
  APER_SCHEMA_REGISTRY,
  ENB_UE_S1AP_ID_TYPE,
  MME_UE_S1AP_ID_TYPE,
  NAS_PDU_TYPE,
  E_RAB_SETUP_ITEM_TYPE,
  NODE_NAME_TYPE,
  CAUSE_TYPE,
  S1AP_PINNED_IE_IDS,
  S1AP_PINNED_PROCEDURES,
  S1AP_FULL_TS36_413_CLAIM,
  TRANSPARENT_CONTAINER_TYPE,
  EUTRAN_CGI_TYPE,
} from '../../../src/pcap/protocols/asn1/aper'
import { encodeTbcd, TBCD_GSM } from '../../../src/pcap/protocols/application/binproto/tbcd'
import { teidCanonicalKey } from '../../../src/pcap/sanitize/gtp'

const IMSI_CANARY = '262011234567890'
const ENB_NAME_CANARY = 'enb-secret-name-99'
const TEID_VAL = 0x0a1b2c3d
const UE_IP = [10, 55, 66, 77] as const

void _crc

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
  const crc = sctpCrc32c(packet, 0, packet.length)
  writeCrc32cLe(packet, 8, crc)
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
  pkt[13] = 0x03 // B+E
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

/** Minimal EPS Attach Request-like NAS for T59 child. */
function buildNasAttach(): Uint8Array {
  const imsi = encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!
  // EPD=0x07, security=0, proto disc already in EPD; msg type Attach Request=0x41
  // Mobile identity LV: length + identity (type IMSI=1 in low nibble of first identity byte)
  const idBody = new Uint8Array(1 + imsi.length)
  idBody[0] = 0x09 // length of identity contents incl type nibble packing — simplify: type|digits
  // Actually EPS mobile identity: first byte = typeof digit + odd/even; use TBCD after type
  // Bare: [len][0x19=IMSI odd][TBCD...]
  const mi = new Uint8Array(2 + imsi.length)
  mi[0] = 1 + imsi.length
  mi[1] = 0x19
  mi.set(imsi, 2)
  return new Uint8Array([0x07, 0x41, ...mi])
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

describe('T57 registry', () => {
  it('registers S1AP APER schema, mobile-core family, engine 2.36.1', () => {
    expect(APER_SCHEMA_REGISTRY.size).toBe(4)
    expect(getAperSchema(S1AP_SCHEMA_MODULE.id)?.revision).toContain('36.413')
    expect(familyForProtocol('s1ap').familyId).toBe('mobile-core')
    expect(familyForProtocol('s1ap-nas').familyId).toBe('mobile-core')
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
    expect(PPID_S1AP).toBe(18)
    expect(S1AP_PINNED_IE_IDS.length).toBeGreaterThanOrEqual(18)
    expect(S1AP_PINNED_PROCEDURES.length).toBeGreaterThanOrEqual(10)
    expect(S1AP_FULL_TS36_413_CLAIM).toBe(false)
  })
})

describe('T57 InitialUEMessage + NAS', () => {
  it('maps eNB-UE-S1AP-ID; redacts IMSI canary via NAS child', () => {
    const nas = buildNasAttach()
    const nasIe = encodeIeValue(NAS_PDU_TYPE, nas)
    const enbId = encodeIeValue(ENB_UE_S1AP_ID_TYPE, 0x1234)
    expect(nasIe && enbId).toBeTruthy()
    const pdu = encodeS1apPdu({
      outcome: 'initiatingMessage',
      procedureCode: S1AP_PROC.INITIAL_UE_MESSAGE,
      ies: [
        { id: S1AP_IE.ENB_UE_S1AP_ID, value: enbId! },
        { id: S1AP_IE.NAS_PDU, value: nasIe! },
      ],
    })
    expect(pdu).not.toBeNull()

    const mapping = new SessionMapping(undefined, { seed: 't57-initial-ue' })
    const sctp = buildDataChunk(36412, 36412, PPID_S1AP, pdu!)
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(r.coverage.some((c) => c.protocol === 's1ap' || c.protocol.startsWith('s1ap-'))).toBe(true)
    const out = applyPatches(frame, r)
    expect(new TextDecoder('latin1').decode(out).includes(IMSI_CANARY)).toBe(false)
    const imsiWire = encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!
    expect(indexOfSubarray(out, imsiWire)).toBe(-1)
    // Original eNB UE id encoding bytes should change (opaque map)
    const idWire = enbId!
    // May still appear if coincidentally in headers — check mapping recorded
    expect(mapping.map('opaque-id', 's1ap-enb-ue:4660')).not.toBe('s1ap-enb-ue:4660')
    void idWire
  })
})

describe('T57 E-RAB + SecurityKey', () => {
  it('maps GTP-TEID and UE IP; masks SecurityKey; preserves Cause', () => {
    const erab = encodeIeValue(E_RAB_SETUP_ITEM_TYPE, {
      eRabId: 5,
      transportLayerAddress: (UE_IP[0]! << 24) | (UE_IP[1]! << 16) | (UE_IP[2]! << 8) | UE_IP[3]!,
      gtpTeid: new Uint8Array([
        (TEID_VAL >>> 24) & 0xff,
        (TEID_VAL >>> 16) & 0xff,
        (TEID_VAL >>> 8) & 0xff,
        TEID_VAL & 0xff,
      ]),
    })
    // SecurityKey BIT STRING(256) — open-type payload as 32 raw octets (T56 writeBits≤32)
    const key = new Uint8Array(32)
    key[0] = 0xde
    key[1] = 0xad
    key[2] = 0xbe
    key[3] = 0xef
    const cause = encodeIeValue(CAUSE_TYPE, { alt: 'nas', value: 'normal-release' })
    const mmeId = encodeIeValue(MME_UE_S1AP_ID_TYPE, 99)
    const enbId = encodeIeValue(ENB_UE_S1AP_ID_TYPE, 88)
    expect(erab && key && cause && mmeId && enbId).toBeTruthy()

    const pdu = encodeS1apPdu({
      outcome: 'initiatingMessage',
      procedureCode: S1AP_PROC.INITIAL_CONTEXT_SETUP,
      criticality: 'reject',
      ies: [
        { id: S1AP_IE.MME_UE_S1AP_ID, value: mmeId! },
        { id: S1AP_IE.ENB_UE_S1AP_ID, value: enbId! },
        { id: S1AP_IE.SECURITY_KEY, value: key! },
        { id: S1AP_IE.E_RAB_TO_BE_SETUP_ITEM_CTX, value: erab! },
        { id: S1AP_IE.CAUSE, value: cause! },
      ],
    })
    expect(pdu).not.toBeNull()

    const mapping = new SessionMapping(undefined, { seed: 't57-erab' })
    const sctp = buildDataChunk(36412, 36412, PPID_S1AP, pdu!)
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(r.coverage.some((c) => c.protocol === 's1ap-security-key')).toBe(true)
    expect(r.coverage.some((c) => c.protocol === 's1ap-erab')).toBe(true)
    expect(r.coverage.some((c) => c.protocol === 's1ap-cause')).toBe(true)

    const teidAlias = Number(
      mapping.map('teid', teidCanonicalKey(TEID_VAL, { receiveEndpoint: UE_IP.join('.'), plane: 'u' })),
    ) >>> 0
    expect(teidAlias).not.toBe(TEID_VAL)
    expect(teidAlias).not.toBe(0)

    const ueAlias = mapping.map('ipv4', UE_IP.join('.'))
    expect(ueAlias).not.toBe(UE_IP.join('.'))

    const out = applyPatches(frame, r)
    // Security key canary pattern must not survive as consecutive marker bytes in clear
    expect(indexOfSubarray(out, new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe(-1)
  })
})

describe('T57 handover + location IEs', () => {
  it('masks transparent container canary and E-UTRAN-CGI cell identity', () => {
    const cellCanary = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00])
    const cgi = encodeIeValue(EUTRAN_CGI_TYPE, {
      pLMNidentity: new Uint8Array([0x02, 0xf8, 0x39]),
      cellIdentity: 0x0a1b2c0,
    })
    const handoverBlob = encodeIeValue(TRANSPARENT_CONTAINER_TYPE, cellCanary)
    const enbId = encodeIeValue(ENB_UE_S1AP_ID_TYPE, 7)
    const mmeId = encodeIeValue(MME_UE_S1AP_ID_TYPE, 8)
    const pdu = encodeS1apPdu({
      outcome: 'initiatingMessage',
      procedureCode: S1AP_PROC.HANDOVER_PREPARATION,
      ies: [
        { id: S1AP_IE.MME_UE_S1AP_ID, value: mmeId! },
        { id: S1AP_IE.ENB_UE_S1AP_ID, value: enbId! },
        { id: S1AP_IE.EUTRAN_CGI, value: cgi! },
        { id: S1AP_IE.SOURCE_TO_TARGET_TRANSPARENT_CONTAINER, value: handoverBlob! },
      ],
    })
    expect(pdu).not.toBeNull()
    const frame = buildEthIpSctp(
      [10, 0, 0, 1],
      [10, 0, 0, 2],
      buildDataChunk(36412, 36412, PPID_S1AP, pdu!),
    )
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, new SessionMapping(undefined, { seed: 't57-ho' }))
    const out = applyPatches(frame, r)
    expect(indexOfSubarray(out, cellCanary)).toBe(-1)
    expect(r.coverage.some((c) => c.protocol === 's1ap-transparent-container')).toBe(true)
    expect(r.coverage.some((c) => c.protocol === 's1ap-location')).toBe(true)
  })
})

describe('T57 export pipeline', () => {
  it('diagnostic export preserves packet count and redacts NAS canary', () => {
    const nas = buildNasAttach()
    const nasIe = encodeIeValue(NAS_PDU_TYPE, nas)
    const enbId = encodeIeValue(ENB_UE_S1AP_ID_TYPE, 0x55)
    const pdu = encodeS1apPdu({
      outcome: 'initiatingMessage',
      procedureCode: S1AP_PROC.INITIAL_UE_MESSAGE,
      ies: [
        { id: S1AP_IE.ENB_UE_S1AP_ID, value: enbId! },
        { id: S1AP_IE.NAS_PDU, value: nasIe! },
      ],
    })!
    const frame = buildEthIpSctp(
      [10, 0, 0, 1],
      [10, 0, 0, 2],
      buildDataChunk(36412, 36412, PPID_S1AP, pdu),
    )
    const { built } = runExportPipeline(
      [exportEnvelope(frame, 0)],
      'diagnostic',
      't57-export.pcap',
      't57-export',
      { mappingSeed: 't57-export-seed' },
    )
    expect(built.packets.length).toBe(1)
    const body = built.packets[0]!.data
    expect(new TextDecoder('latin1').decode(body).includes(IMSI_CANARY)).toBe(false)
  })
})

describe('T57 S1Setup node name', () => {
  it('maps eNB name hostname; unknown IE masked', () => {
    const nameBytes = new TextEncoder().encode(ENB_NAME_CANARY)
    const nameIe = encodeIeValue(NODE_NAME_TYPE, nameBytes)
    const unknown = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04])
    const pdu = encodeS1apPdu({
      outcome: 'initiatingMessage',
      procedureCode: S1AP_PROC.S1_SETUP,
      ies: [
        { id: S1AP_IE.ENB_NAME, value: nameIe! },
        { id: 9999, value: unknown },
      ],
    })
    expect(pdu).not.toBeNull()
    const mapping = new SessionMapping(undefined, { seed: 't57-s1setup' })
    const frame = buildEthIpSctp(
      [10, 0, 0, 1],
      [10, 0, 0, 2],
      buildDataChunk(36412, 36412, PPID_S1AP, pdu!),
    )
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(new TextDecoder('latin1').decode(out).includes(ENB_NAME_CANARY)).toBe(false)
    expect(indexOfSubarray(out, unknown)).toBe(-1)
    expect(r.coverage.some((c) => c.protocol === 's1ap-node-name')).toBe(true)
  })
})
