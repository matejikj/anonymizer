/**
 * T61 — 5G SBI HTTP/JSON + multipart N1/N2 (pinned REL-18 subset).
 */
import { describe, expect, it } from 'vitest'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { buildProtocolSupportMatrix } from '../../../src/pcap/docs/protocolSupportMatrix'
import {
  SBI_PINNED_OPERATIONS,
  SBI_SCHEMA_PIN,
  looksLikeSbi,
  sanitizeSbi5g,
} from '../../../src/pcap/sanitize/sbi5g'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { encodeN2Transfer } from '../../../src/pcap/sanitize/ngap'
import { encodeTbcd, TBCD_GSM } from '../../../src/pcap/protocols/application/binproto/tbcd'
import { IPPROTO_TCP } from '../../../src/pcap/protocols/types'

const SUPI = 'imsi-262019876543210'
const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sbi-secret-token-61'
const NF_ID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
const TEID_VAL = 0x11223344
const UE_IP = [10, 66, 77, 88] as const
const IMSI_CANARY = '262019876543210'
const DNN = 'internet.home-secret.example'
const CALLBACK = 'https://pcf.example.5gc/n1-callback?token=super-secret-callback-token'

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

function buildEthIpTcp(payload: Uint8Array, srcPort = 40_000, dstPort = 8080): Uint8Array {
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
  buf[23] = IPPROTO_TCP
  buf.set([10, 0, 0, 1], 26)
  buf.set([10, 0, 0, 2], 30)
  const tcpOff = 34
  buf[tcpOff] = (srcPort >> 8) & 0xff
  buf[tcpOff + 1] = srcPort & 0xff
  buf[tcpOff + 2] = (dstPort >> 8) & 0xff
  buf[tcpOff + 3] = dstPort & 0xff
  buf[tcpOff + 12] = 0x50 // data offset 5
  buf[tcpOff + 13] = 0x18 // PSH+ACK
  buf.set(payload, tcpOff + 20)
  return buf
}

function buildNasRegistration(): Uint8Array {
  const imsi = encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!
  const mi = new Uint8Array(2 + imsi.length)
  mi[0] = 1 + imsi.length
  mi[1] = 0x01
  mi.set(imsi, 2)
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

function indexOfBytes(hay: Uint8Array, needle: string | Uint8Array): number {
  const n = typeof needle === 'string' ? new TextEncoder().encode(needle) : needle
  outer: for (let i = 0; i <= hay.length - n.length; i++) {
    for (let j = 0; j < n.length; j++) {
      if (hay[i + j] !== n[j]) continue outer
    }
    return i
  }
  return -1
}

describe('T61 registry', () => {
  it('registers sbi5g handler, mobile-core family, pinned ops, engine 2.35.0', () => {
    expect(APPLICATION_HANDLER_ORDER.some((h) => h.id === 'sbi5g')).toBe(true)
    expect(familyForProtocol('sbi5g').familyId).toBe('mobile-core')
    expect(familyForProtocol('sbi5g-n2').familyId).toBe('mobile-core')
    expect(SBI_PINNED_OPERATIONS.length).toBeGreaterThanOrEqual(12)
    expect(SBI_SCHEMA_PIN.release).toBe('REL-18')
    expect(PCAP_ENGINE_VERSION).toBe('2.35.0')
    expect(buildProtocolSupportMatrix().some((r) => r.id === 'app:sbi5g')).toBe(true)
  })
})

describe('T61 NRF / token', () => {
  it('maps nfInstanceId and masks accessToken; preserves status', () => {
    const body = JSON.stringify({
      nfInstanceId: NF_ID,
      accessToken: TOKEN,
      status: 'REGISTERED',
      ipv4Address: '10.1.2.3',
    })
    const http = TEXT_ENC(
      `PUT /nnrf-nfm/v1/nf-instances/${NF_ID} HTTP/1.1\r\n` +
        `Host: nrf.example.5gc\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${body.length}\r\n` +
        `\r\n` +
        body,
    )
    expect(looksLikeSbi(http, 0, http.length)).toBe(true)
    const mapping = new SessionMapping(undefined, { seed: 't61-nrf' })
    const frame = buildEthIpTcp(http)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(r.coverage.some((c) => c.protocol.startsWith('sbi5g'))).toBe(true)
    const out = applyPatches(frame, r)
    expect(indexOfBytes(out, TOKEN)).toBe(-1)
    expect(indexOfBytes(out, NF_ID)).toBe(-1)
    expect(indexOfBytes(out, 'REGISTERED')).toBeGreaterThanOrEqual(0)
    expect(indexOfBytes(out, '10.1.2.3')).toBe(-1)
  })
})

describe('T61 Namf / Nsmf SUPI', () => {
  it('maps SUPI in path and JSON; masks ProblemDetails detail', () => {
    const body = JSON.stringify({
      supi: SUPI,
      pduSessionId: '5',
      detail: 'subscriber-home-secret-detail',
      cause: 'USER_UNKNOWN',
      '5qi': 9,
    })
    const http = TEXT_ENC(
      `POST /namf-comm/v1/ue-contexts/${SUPI}/n1-n2-messages HTTP/1.1\r\n` +
        `Host: amf.example.5gc\r\n` +
        `Authorization: Bearer ${TOKEN}\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${body.length}\r\n` +
        `\r\n` +
        body,
    )
    const mapping = new SessionMapping(undefined, { seed: 't61-namf' })
    const frame = buildEthIpTcp(http)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(indexOfBytes(out, SUPI)).toBe(-1)
    expect(indexOfBytes(out, TOKEN)).toBe(-1)
    expect(indexOfBytes(out, 'subscriber-home-secret-detail')).toBe(-1)
    expect(indexOfBytes(out, 'USER_UNKNOWN')).toBeGreaterThanOrEqual(0)
    expect(indexOfBytes(out, '"5qi":9') >= 0 || indexOfBytes(out, '"5qi": 9') >= 0).toBe(true)
  })
})

describe('T61 multipart N1 + typed N2', () => {
  it('dispatches NAS child and N2 transfer by schemaTypeId', () => {
    const nas = buildNasRegistration()
    const transfer = encodeN2Transfer('ngap.PDUSessionResourceSetupRequestTransfer', {
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
    })
    expect(transfer).not.toBeNull()

    const boundary = 'sbi61bound'
    const jsonPart =
      `Content-Type: application/json\r\n\r\n` +
      JSON.stringify({
        supi: SUPI,
        n2InfoContainer: { n2InformationClass: 'SM' },
      })
    const nasPart =
      `Content-Type: application/vnd.3gpp.5gnas\r\n` +
      `Content-Id: <n1>\r\n\r\n`
    const n2Part =
      `Content-Type: application/vnd.3gpp.ngap; type="PDUSessionResourceSetupRequestTransfer"\r\n` +
      `Content-Id: <n2>\r\n\r\n`

    const enc = new TextEncoder()
    const chunks: Uint8Array[] = []
    chunks.push(enc.encode(`--${boundary}\r\n${jsonPart}\r\n`))
    chunks.push(enc.encode(`--${boundary}\r\n${nasPart}`))
    chunks.push(nas)
    chunks.push(enc.encode(`\r\n--${boundary}\r\n${n2Part}`))
    chunks.push(transfer!)
    chunks.push(enc.encode(`\r\n--${boundary}--\r\n`))
    const bodyLen = chunks.reduce((n, c) => n + c.length, 0)
    const body = new Uint8Array(bodyLen)
    let o = 0
    for (const c of chunks) {
      body.set(c, o)
      o += c.length
    }

    const header = enc.encode(
      `POST /nsmf-pdusession/v1/sm-contexts HTTP/1.1\r\n` +
        `Host: smf.example.5gc\r\n` +
        `Content-Type: multipart/related; boundary=${boundary}\r\n` +
        `Content-Length: ${body.length}\r\n` +
        `\r\n`,
    )
    const http = new Uint8Array(header.length + body.length)
    http.set(header, 0)
    http.set(body, header.length)

    const mapping = new SessionMapping(undefined, { seed: 't61-mime' })
    const frame = buildEthIpTcp(http)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(r.coverage.some((c) => c.protocol.includes('sbi5g-n1') || c.protocol.includes('nas'))).toBe(
      true,
    )
    expect(r.coverage.some((c) => c.protocol.includes('sbi5g-n2') || c.protocol.includes('ngap-n2'))).toBe(
      true,
    )
    const out = applyPatches(frame, r)
    expect(indexOfBytes(out, SUPI)).toBe(-1)
    expect(indexOfBytes(out, IMSI_CANARY)).toBe(-1)
    const teidWire = new Uint8Array([
      (TEID_VAL >>> 24) & 0xff,
      (TEID_VAL >>> 16) & 0xff,
      (TEID_VAL >>> 8) & 0xff,
      TEID_VAL & 0xff,
    ])
    expect(indexOfBytes(out, teidWire)).toBe(-1)
    expect(indexOfBytes(out, new Uint8Array(UE_IP))).toBe(-1)
  })
})

describe('T61 UDM / PCF / NSSF / NEF (T61.3–.4)', () => {
  it('GET nudm-sdm maps SUPI in path', () => {
    const http = TEXT_ENC(
      `GET /nudm-sdm/v2/${SUPI}/am-data HTTP/1.1\r\n` +
        `Host: udm.example.5gc\r\n` +
        `\r\n`,
    )
    const mapping = new SessionMapping(undefined, { seed: 't61-udm' })
    const frame = buildEthIpTcp(http)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(r.coverage.some((c) => c.protocol === 'sbi5g-nudm')).toBe(true)
    expect(indexOfBytes(out, SUPI)).toBe(-1)
  })

  it('POST npcf sm-policy maps SUPI/DNN and callback URI; preserves sst', () => {
    const body = JSON.stringify({
      supi: SUPI,
      dnn: DNN,
      notificationUri: CALLBACK,
      sst: 1,
      sd: '010203',
    })
    const http = TEXT_ENC(
      `POST /npcf-smpolicycontrol/v1/sm-policies HTTP/1.1\r\n` +
        `Host: pcf.example.5gc\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${body.length}\r\n` +
        `\r\n` +
        body,
    )
    const mapping = new SessionMapping(undefined, { seed: 't61-pcf' })
    const frame = buildEthIpTcp(http)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(r.coverage.some((c) => c.protocol === 'sbi5g-npcf')).toBe(true)
    expect(indexOfBytes(out, SUPI)).toBe(-1)
    expect(indexOfBytes(out, DNN)).toBe(-1)
    expect(indexOfBytes(out, 'super-secret-callback-token')).toBe(-1)
    expect(indexOfBytes(out, '"sst":1') >= 0 || indexOfBytes(out, '"sst": 1') >= 0).toBe(true)
  })

  it('GET nnssf slice query maps PLMN; preserves requested sst', () => {
    const http = TEXT_ENC(
      `GET /nnssf-nsselection/v1/network-slice-information?` +
        `nf-type=AMF&requester-nf-type=AMF&snssai-sst=1&snssai-sd=010203&` +
        `serving-plmn-mcc=262&serving-plmn-mnc=01 HTTP/1.1\r\n` +
        `Host: nssf.example.5gc\r\n` +
        `\r\n`,
    )
    const mapping = new SessionMapping(undefined, { seed: 't61-nssf' })
    const frame = buildEthIpTcp(http)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(r.coverage.some((c) => c.protocol === 'sbi5g-nnssf')).toBe(true)
    expect(indexOfBytes(out, 'snssai-sst=')).toBeGreaterThanOrEqual(0)
    expect(indexOfBytes(out, 'serving-plmn-mcc=262')).toBe(-1)
  })

  it('POST nnef subscription maps callbackReference', () => {
    const body = JSON.stringify({
      notificationDestination: CALLBACK,
      supi: SUPI,
      event: 'UE_REACHABILITY',
    })
    const http = TEXT_ENC(
      `POST /nnef-eventexposure/v1/subscriptions HTTP/1.1\r\n` +
        `Host: nnef.example.5gc\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${body.length}\r\n` +
        `\r\n` +
        body,
    )
    const mapping = new SessionMapping(undefined, { seed: 't61-nnef' })
    const frame = buildEthIpTcp(http)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(r.coverage.some((c) => c.protocol === 'sbi5g-nnef')).toBe(true)
    expect(indexOfBytes(out, SUPI)).toBe(-1)
    expect(indexOfBytes(out, 'super-secret-callback-token')).toBe(-1)
  })
})

describe('T61 SMF release + AMF subscription (T61.2)', () => {
  it('POST sm-context release maps smContextRef in path', () => {
    const ref = 'smctx-61-release-ref'
    const body = JSON.stringify({ cause: 'PDU_SESSION_RELEASED' })
    const http = TEXT_ENC(
      `POST /nsmf-pdusession/v1/sm-contexts/${ref}/release HTTP/1.1\r\n` +
        `Host: smf.example.5gc\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${body.length}\r\n` +
        `\r\n` +
        body,
    )
    const mapping = new SessionMapping(undefined, { seed: 't61-smf-rel' })
    const frame = buildEthIpTcp(http)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(indexOfBytes(out, ref)).toBe(-1)
    expect(indexOfBytes(out, 'PDU_SESSION_RELEASED')).toBeGreaterThanOrEqual(0)
  })

  it('POST namf-evts subscription maps notificationUri', () => {
    const body = JSON.stringify({
      notificationUri: CALLBACK,
      supi: SUPI,
      eventList: [{ type: 'LOCATION_REPORT' }],
    })
    const http = TEXT_ENC(
      `POST /namf-evts/v1/subscriptions HTTP/1.1\r\n` +
        `Host: amf.example.5gc\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${body.length}\r\n` +
        `\r\n` +
        body,
    )
    const mapping = new SessionMapping(undefined, { seed: 't61-amf-evts' })
    const frame = buildEthIpTcp(http)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(r.coverage.some((c) => c.protocol === 'sbi5g-namf')).toBe(true)
    expect(indexOfBytes(out, SUPI)).toBe(-1)
    expect(indexOfBytes(out, 'super-secret-callback-token')).toBe(-1)
  })
})

describe('T61 export pipeline', () => {
  it('diagnostic export keeps one TCP frame and redacts SUPI/token canaries', () => {
    const body = JSON.stringify({
      supi: SUPI,
      pduSessionId: '5',
      cause: 'USER_UNKNOWN',
    })
    const http = TEXT_ENC(
      `POST /namf-comm/v1/ue-contexts/${SUPI}/n1-n2-messages HTTP/1.1\r\n` +
        `Host: amf.example.5gc\r\n` +
        `Authorization: Bearer ${TOKEN}\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${body.length}\r\n` +
        `\r\n` +
        body,
    )
    const frame = buildEthIpTcp(http)
    const { built } = runExportPipeline(
      [exportEnvelope(frame, 0)],
      'diagnostic',
      't61-export.pcap',
      't61-export',
      { mappingSeed: 't61-export-seed' },
    )
    expect(built.packets.length).toBe(1)
    const wire = built.packets[0]!.data
    expect(new TextDecoder('latin1').decode(wire).includes(SUPI)).toBe(false)
    expect(new TextDecoder('latin1').decode(wire).includes(TOKEN)).toBe(false)
    expect(new TextDecoder('latin1').decode(wire).includes('USER_UNKNOWN')).toBe(true)
  })
})

describe('T61 AUSF auth vectors', () => {
  it('masks RAND/AUTN always', () => {
    const body = JSON.stringify({
      supiOrSuci: SUPI,
      authType: '5G_AKA',
      rand: '00112233445566778899aabbccddeeff',
      autn: 'ffeeddccbbaa99887766554433221100',
      authResult: 'SUCCESS',
    })
    // Map unknown key supiOrSuci via mask; put explicit rand/autn
    const http = TEXT_ENC(
      `POST /nausf-auth/v1/ue-authentications HTTP/1.1\r\n` +
        `Host: ausf.example.5gc\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${body.length}\r\n` +
        `\r\n` +
        body,
    )
    const mapping = new SessionMapping(undefined, { seed: 't61-ausf' })
    const collector = new PatchCollector()
    const direct = sanitizeSbi5g(http, 0, http.length, collector, mapping, undefined, 0)
    expect(direct?.coverage.some((c) => c.protocol.startsWith('sbi5g'))).toBe(true)

    const frame = buildEthIpTcp(http)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(indexOfBytes(out, '00112233445566778899aabbccddeeff')).toBe(-1)
    expect(indexOfBytes(out, 'ffeeddccbbaa99887766554433221100')).toBe(-1)
    expect(indexOfBytes(out, 'SUCCESS')).toBeGreaterThanOrEqual(0)
  })
})

function TEXT_ENC(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}
