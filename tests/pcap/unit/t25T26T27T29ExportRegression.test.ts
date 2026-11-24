/**
 * T25/T26/T27/T29 — processCapture → plan → export synthetic regression (canaries + correlations).
 */
import { describe, expect, it, beforeEach } from 'vitest'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { runProcessCaptureExportPipeline } from '../helpers/processCaptureExportPipeline'
import { assertCaptureHasNoPrivacyLeaks } from '../helpers/privacyLeakScan'
import { buildEthIpTcp, buildEthIpUdp } from '../fixtures/voipCorpus'
import { encodeTbcd, TBCD_GSM } from '../../../src/pcap/protocols/application/binproto/tbcd'
import { sctpCrc32c, writeCrc32cLe } from '../../../src/crypto/crc32c'
import { IPPROTO_SCTP } from '../../../src/pcap/protocols/types'
import { GTP_C_UDP_PORT, GTP_U_UDP_PORT } from '../../../src/pcap/sanitize/gtp'
import { PPID_M2PA } from '../../../src/pcap/sanitize/m2pa.ts'
import { resetProtocolGraphStateRegistryForTests } from '../../../src/pcap/sanitize/protocolGraphState'

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

function envelope(data: Uint8Array, index = 0): PacketEnvelope {
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
  const crc = sctpCrc32c(buf, 0, buf.length)
  writeCrc32cLe(buf, 8, crc)
  return buf
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
  pkt[24] = (ppid >>> 24) & 0xff
  pkt[25] = (ppid >>> 16) & 0xff
  pkt[26] = (ppid >>> 8) & 0xff
  pkt[27] = ppid & 0xff
  pkt.set(user, 28)
  const crc = sctpCrc32c(pkt, 0, pkt.length)
  writeCrc32cLe(pkt, 8, crc)
  return pkt
}

function buildM3uaProtocolData(opc: number, dpc: number, si: number, user: Uint8Array): Uint8Array {
  const pdValueLen = 12 + user.length
  const pdParamLen = 4 + pdValueLen
  const pdPadded = (pdParamLen + 3) & ~3
  const msgLen = 8 + pdPadded
  const out = new Uint8Array(msgLen)
  out[0] = 1
  out[1] = 0
  out[2] = 1
  out[3] = 1
  out[4] = (msgLen >>> 24) & 0xff
  out[5] = (msgLen >>> 16) & 0xff
  out[6] = (msgLen >>> 8) & 0xff
  out[7] = msgLen & 0xff
  out[8] = 0x02
  out[9] = 0x10
  out[10] = (pdParamLen >> 8) & 0xff
  out[11] = pdParamLen & 0xff
  const v = 12
  out[v] = (opc >>> 24) & 0xff
  out[v + 1] = (opc >>> 16) & 0xff
  out[v + 2] = (opc >>> 8) & 0xff
  out[v + 3] = opc & 0xff
  out[v + 4] = (dpc >>> 24) & 0xff
  out[v + 5] = (dpc >>> 16) & 0xff
  out[v + 6] = (dpc >>> 8) & 0xff
  out[v + 7] = dpc & 0xff
  out[v + 8] = si
  out.set(user, v + 12)
  return out
}

function buildIsupIam(calledDigits: string): Uint8Array {
  const tbcd = encodeTbcd(calledDigits, Math.ceil(calledDigits.length / 2), TBCD_GSM)!
  const calledContents = new Uint8Array(2 + tbcd.length)
  calledContents[0] = 0x83
  calledContents[1] = 0x10
  calledContents.set(tbcd, 2)
  const out = new Uint8Array(2 + 1 + 5 + 2 + 1 + calledContents.length)
  out[0] = 0x34
  out[1] = 0x12
  out[2] = 0x01
  out[8] = 2
  out[10] = calledContents.length
  out.set(calledContents, 11)
  return out
}

const IMSI_CANARY = '262011234567890'
const UE_IP = [10, 55, 66, 77] as const
const F_TEID_VAL = 0x0a1b2c3d

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
  const total = parts.reduce((s, p) => s + p.length, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

function buildCreateSessionRequest(): Uint8Array {
  const imsi = encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!
  const fteid = concat(new Uint8Array([0x81]), u32be(F_TEID_VAL), new Uint8Array([10, 1, 2, 3]))
  const paa = concat(new Uint8Array([1]), new Uint8Array(UE_IP))
  const ies = concat(v2Ie(1, imsi), v2Ie(87, fteid), v2Ie(79, paa))
  const hdr = new Uint8Array(12)
  hdr[0] = 0x48
  hdr[1] = 32
  const msgLen = 8 + ies.length
  hdr[2] = (msgLen >> 8) & 0xff
  hdr[3] = msgLen & 0xff
  hdr[8] = 0
  hdr[9] = 1
  hdr[10] = 2
  return concat(hdr, ies)
}

function buildInnerIpv4Sip(srcIp: readonly number[], sipCanary: string): Uint8Array {
  const sip = new TextEncoder().encode(
    `INVITE sip:user@example.com SIP/2.0\r\nCall-ID: ${sipCanary}\r\n\r\n`,
  )
  const ipLen = 20 + 8 + sip.length
  const pkt = new Uint8Array(ipLen)
  pkt[0] = 0x45
  pkt[2] = (ipLen >> 8) & 0xff
  pkt[3] = ipLen & 0xff
  pkt[9] = 17
  pkt.set(srcIp, 12)
  pkt.set([10, 0, 0, 1], 16)
  const udp = 20
  pkt[udp + 1] = 0xc4
  pkt[udp + 3] = 0xc4
  const udpLen = 8 + sip.length
  pkt[udp + 4] = (udpLen >> 8) & 0xff
  pkt[udp + 5] = udpLen & 0xff
  pkt.set(sip, udp + 8)
  return pkt
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

function readTeidBe(buf: Uint8Array, offset: number): number {
  return ((buf[offset]! << 24) | (buf[offset + 1]! << 16) | (buf[offset + 2]! << 8) | buf[offset + 3]!) >>> 0
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

function buildSccpUdtE214Gt(e214Digits: string): Uint8Array {
  const gtTbcd = encodeTbcd(e214Digits, Math.ceil(e214Digits.length / 2), TBCD_GSM)!
  const calledAddr = new Uint8Array(1 + 1 + 1 + 1 + gtTbcd.length)
  calledAddr[0] = calledAddr.length - 1
  calledAddr[1] = 0x0e
  calledAddr[2] = 0x06
  calledAddr[3] = 0x60
  calledAddr.set(gtTbcd, 4)
  const callingAddr = new Uint8Array([2, 0x02, 0x07])
  const dataParam = new Uint8Array([0])
  const body = new Uint8Array(calledAddr.length + callingAddr.length + dataParam.length)
  body.set(calledAddr, 0)
  body.set(callingAddr, calledAddr.length)
  body.set(dataParam, calledAddr.length + callingAddr.length)
  const out = new Uint8Array(5 + body.length)
  out[0] = 0x09
  out[1] = 0x81
  out[2] = 3
  out[3] = 2 + calledAddr.length
  out[4] = 1 + calledAddr.length + callingAddr.length
  out.set(body, 5)
  return out
}

describe('T25 SIGTRAN export (processCapture)', () => {
  it('export omits E.214 SCCP GT canary (T25.spec E.214)', async () => {
    const e214 = '262011234567890'
    const sccp = buildSccpUdtE214Gt(e214)
    const m3ua = buildM3uaProtocolData(0x10, 0x20, 3, sccp)
    const sctp = buildDataChunk(2905, 2905, 3, m3ua)
    const frame = buildEthIpSctp([10, 2, 0, 1], [10, 2, 0, 2], sctp)
    const { built } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't25-e214-export.pcap',
      't25-e214-export',
      { mappingSeed: 't25-e214-export' },
    )
    expect(built.validationValid).toBe(true)
    assertCaptureHasNoPrivacyLeaks(built.packets[0]!.data, [e214])
  })

  it('export omits M2PA ANSI PC and protocol canary (T25.spec M2PA)', async () => {
    const dpc = 0x0a0b0c
    const opc = 0x0d0e0f
    const proto = new TextEncoder().encode('M2PA-EXPORT-PROTO-CANARY')
    const bodyLen = 4 + 7 + proto.length
    const msgLen = 10 + bodyLen
    const m2pa = new Uint8Array(msgLen)
    m2pa[0] = 1
    m2pa[2] = 0
    m2pa[3] = 11
    m2pa[4] = 0
    m2pa[5] = 1
    m2pa[6] = (msgLen >>> 24) & 0xff
    m2pa[7] = (msgLen >>> 16) & 0xff
    m2pa[8] = (msgLen >>> 8) & 0xff
    m2pa[9] = msgLen & 0xff
    m2pa[14] = (dpc >>> 16) & 0xff
    m2pa[15] = (dpc >>> 8) & 0xff
    m2pa[16] = dpc & 0xff
    m2pa[17] = (opc >>> 16) & 0xff
    m2pa[18] = (opc >>> 8) & 0xff
    m2pa[19] = opc & 0xff
    m2pa.set(proto, 21)
    const sctp = buildDataChunk(2905, 2905, PPID_M2PA, m2pa)
    const frame = buildEthIpSctp([10, 5, 0, 1], [10, 5, 0, 2], sctp)
    const { built } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't25-m2pa-export.pcap',
      't25-m2pa-export',
      { mappingSeed: 't25-m2pa-export' },
    )
    expect(built.validationValid).toBe(true)
    assertCaptureHasNoPrivacyLeaks(built.packets[0]!.data, ['M2PA-EXPORT-PROTO-CANARY'])
  })

  it('export omits ISUP called-party and raw OPC/DPC canaries (T25.export)', async () => {
    const called = '420123456789'
    const opc = 0x001122
    const dpc = 0x003344
    const isup = buildIsupIam(called)
    const m3ua = buildM3uaProtocolData(opc, dpc, 5, isup)
    const sctp = buildDataChunk(2905, 2905, 3, m3ua)
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const { built, session } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't25-export.pcap',
      't25-export',
      { mappingSeed: 't25-export' },
    )
    expect(built.validationValid).toBe(true)
    expect(session.discovery.packetDiscovery[0]?.coverage.some((c) => c.protocol === 'm3ua')).toBe(
      true,
    )
    const wire = built.packets[0]!.data
    assertCaptureHasNoPrivacyLeaks(wire, [called])
    const payload = wire.subarray(34)
    const opcBytes = Buffer.from([(opc >>> 24) & 0xff, (opc >>> 16) & 0xff, (opc >>> 8) & 0xff, opc & 0xff])
    const dpcBytes = Buffer.from([(dpc >>> 24) & 0xff, (dpc >>> 16) & 0xff, (dpc >>> 8) & 0xff, dpc & 0xff])
    expect(Buffer.from(payload).includes(opcBytes)).toBe(false)
    expect(Buffer.from(payload).includes(dpcBytes)).toBe(false)
  })
})

describe('T26 GTP export (processCapture)', () => {
  beforeEach(() => resetProtocolGraphStateRegistryForTests())

  it('export correlates F-TEID alias into GTP-U and UE IP into inner T-PDU (T26.export)', async () => {
    const sipCanary = 'gtp-export-callid-CANARY'
    const csr = buildCreateSessionRequest()
    const frameC = buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], GTP_C_UDP_PORT, GTP_C_UDP_PORT, csr)
    const tpdu = buildInnerIpv4Sip(UE_IP, sipCanary)
    const gtpU = buildGtpU(F_TEID_VAL, tpdu)
    const frameU = buildEthIpUdp([10, 1, 2, 4], [10, 1, 2, 3], GTP_U_UDP_PORT, GTP_U_UDP_PORT, gtpU)

    const { built } = await runProcessCaptureExportPipeline(
      [envelope(frameC, 0), envelope(frameU, 1)],
      'diagnostic',
      't26-export.pcap',
      't26-export',
      { mappingSeed: 't26-export' },
    )
    expect(built.validationValid).toBe(true)
    assertCaptureHasNoPrivacyLeaks(built.packets[1]!.data, [IMSI_CANARY, sipCanary])

    const gtpPayloadOff = 14 + 20 + 8
    const outC = built.packets[0]!.data
    const outU = built.packets[1]!.data
    const teidOut = readTeidBe(outU, gtpPayloadOff + 4)
    expect(teidOut).not.toBe(F_TEID_VAL)
    const rawTeid = u32be(F_TEID_VAL)
    expect(indexOfSubarray(outC, rawTeid)).toBe(-1)
    expect(indexOfSubarray(outU.subarray(gtpPayloadOff), rawTeid)).toBe(-1)
    const innerIpOff = gtpPayloadOff + 8 + 12
    const innerBytes = outU.subarray(innerIpOff, innerIpOff + 4)
    expect(indexOfSubarray(outC, innerBytes)).toBeGreaterThan(gtpPayloadOff)
    expect([...innerBytes]).not.toEqual([...UE_IP])
    expect(indexOfSubarray(outC, new Uint8Array(UE_IP))).toBe(-1)
  })

  it('export masks PCO PAP secret and maps DNS server IP (T26.spec PCO)', async () => {
    const papSecret = 'GTP-EXPORT-PAP-CANARY'
    const papBody = new TextEncoder().encode(papSecret)
    const pco = concat(
      new Uint8Array([0x80]),
      new Uint8Array([0xc0, 0x23, papBody.length]),
      papBody,
      new Uint8Array([0x00, 0x0d, 0x04, 1, 1, 1, 1]),
    )
    const ies = v2Ie(78, pco)
    const hdr = new Uint8Array(12)
    hdr[0] = 0x48
    hdr[1] = 32
    const msgLen = 8 + ies.length
    hdr[2] = (msgLen >> 8) & 0xff
    hdr[3] = msgLen & 0xff
    const csr = concat(hdr, ies)
    const frame = buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], GTP_C_UDP_PORT, GTP_C_UDP_PORT, csr)
    const { built } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't26-pco-export.pcap',
      't26-pco-export',
      { mappingSeed: 't26-pco-export' },
    )
    expect(built.validationValid).toBe(true)
    assertCaptureHasNoPrivacyLeaks(built.packets[0]!.data, [papSecret, '1.1.1.1'])
  })

  it('export sanitizes piggybacked GTPv2-C messages (T26.spec piggyback)', async () => {
    const imsiCanary = '262019998887766'
    const imsi = encodeTbcd(imsiCanary, 8, TBCD_GSM)!
    const msg2Ies = v2Ie(1, imsi)
    const hdr2 = new Uint8Array(12)
    hdr2[0] = 0x48
    hdr2[1] = 32
    const msg2Len = 8 + msg2Ies.length
    hdr2[2] = (msg2Len >> 8) & 0xff
    hdr2[3] = msg2Len & 0xff
    const msg2 = concat(hdr2, msg2Ies)
    const rec = new Uint8Array([3, 1, 0x01])
    const msg1Ies = v2Ie(3, rec)
    const hdr1 = new Uint8Array(12)
    hdr1[0] = 0x58
    hdr1[1] = 33
    const msg1Len = 8 + msg1Ies.length
    hdr1[2] = (msg1Len >> 8) & 0xff
    hdr1[3] = msg1Len & 0xff
    const piggy = concat(concat(hdr1, msg1Ies), msg2)
    const frame = buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], GTP_C_UDP_PORT, GTP_C_UDP_PORT, piggy)
    const { built, session } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't26-piggy-export.pcap',
      't26-piggy-export',
      { mappingSeed: 't26-piggy-export' },
    )
    expect(built.validationValid).toBe(true)
    expect(session.discovery.packetDiscovery[0]?.issues?.includes('gtpv2-piggyback')).toBe(true)
    assertCaptureHasNoPrivacyLeaks(built.packets[0]!.data, [imsiCanary])
  })
})

describe('T27 enterprise plaintext export (processCapture)', () => {
  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`export masks SMTP email and AUTH canaries (${level}, T27.export)`, async () => {
      const email = 't27-export-canary@corp.example'
      const authB64 = 'AGFsaWNlAHNlY3JldA=='
      const payload = new TextEncoder().encode(
        `EHLO mail.corp.example\r\nMAIL FROM:<${email}>\r\nAUTH PLAIN ${authB64}\r\n`,
      )
      const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40_000, 25, 1, payload)
      const { built } = await runProcessCaptureExportPipeline(
        [envelope(frame)],
        level,
        `t27-export-${level}.pcap`,
        `t27-export-${level}`,
        { mappingSeed: `t27-export-${level}` },
      )
      expect(built.validationValid).toBe(true)
      const wire = latin1(built.packets[0]!.data)
      expect(wire.includes(email)).toBe(false)
      expect(wire.includes(authB64)).toBe(false)
      assertCaptureHasNoPrivacyLeaks(built.packets[0]!.data, [email, 'alice', 'secret'])
    })
  }
})

describe('T29 database export (processCapture)', () => {
  it('export masks PostgreSQL password and SQL literal canaries (T29.export)', async () => {
    const password = new TextEncoder().encode('PG-EXPORT-PASS-CANARY\0')
    const passLen = 4 + password.length
    const passMsg = new Uint8Array(1 + 4 + password.length)
    passMsg[0] = 0x70
    passMsg[1] = (passLen >> 24) & 0xff
    passMsg[2] = (passLen >> 16) & 0xff
    passMsg[3] = (passLen >> 8) & 0xff
    passMsg[4] = passLen & 0xff
    passMsg.set(password, 5)

    const sql = new TextEncoder().encode("SELECT 'SQL-EXPORT-CANARY'\0")
    const queryLen = 4 + sql.length
    const query = new Uint8Array(1 + 4 + sql.length)
    query[0] = 0x51
    query[1] = (queryLen >> 24) & 0xff
    query[2] = (queryLen >> 16) & 0xff
    query[3] = (queryLen >> 8) & 0xff
    query[4] = queryLen & 0xff
    query.set(sql, 5)

    const payload = new Uint8Array(passMsg.length + query.length)
    payload.set(passMsg, 0)
    payload.set(query, passMsg.length)
    const frame = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5432, 1, payload)

    const { built } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't29-export.pcap',
      't29-export',
      { mappingSeed: 't29-export' },
    )
    expect(built.validationValid).toBe(true)
    const wire = latin1(built.packets[0]!.data)
    expect(wire.includes('PG-EXPORT-PASS-CANARY')).toBe(false)
    expect(wire.includes('SQL-EXPORT-CANARY')).toBe(false)
    assertCaptureHasNoPrivacyLeaks(built.packets[0]!.data, ['PG-EXPORT-PASS-CANARY', 'SQL-EXPORT-CANARY'])
  })
})
