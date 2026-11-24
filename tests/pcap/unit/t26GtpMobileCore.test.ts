/**
 * T26 — GTPv1/v2-C + GTP-U mobile core sanitizer.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { decodeTbcd, encodeTbcd, TBCD_GSM } from '../../../src/pcap/protocols/application/binproto/tbcd'
import { GTP_C_UDP_PORT, GTP_U_UDP_PORT, teidCanonicalKey } from '../../../src/pcap/sanitize/gtp'

const IMSI_CANARY = '262011234567890'
const IMEI_CANARY = '356938035643809'
const MSISDN_DIGITS = '420601234567'
const UE_IP = [10, 55, 66, 77] as const
const F_TEID_VAL = 0x0a1b2c3d

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

function u32be(n: number): Uint8Array {
  return new Uint8Array([
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ])
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

/** GTPv2 Create Session Request with IMSI / MEI / MSISDN / APN / F-TEID / PAA. */
function buildCreateSessionRequest(): Uint8Array {
  const imsi = encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!
  const mei = encodeTbcd(IMEI_CANARY, 8, TBCD_GSM)!
  // MSISDN: TON/NPI byte + TBCD
  const msisdnTbcd = encodeTbcd(MSISDN_DIGITS, 6, TBCD_GSM)!
  const msisdn = concat(new Uint8Array([0x91]), msisdnTbcd)
  // APN labels: internet.mnc001.mcc262.gprs
  const apnLabels = ['internet', 'mnc001', 'mcc262', 'gprs']
  const apnParts: number[] = []
  for (const lab of apnLabels) {
    apnParts.push(lab.length)
    for (let i = 0; i < lab.length; i++) apnParts.push(lab.charCodeAt(i))
  }
  const apn = new Uint8Array(apnParts)
  // F-TEID: V4=1, iface=1 (S5/S8 SGW GTP-U), TEID, IPv4
  const fteid = concat(
    new Uint8Array([0x81]),
    u32be(F_TEID_VAL),
    new Uint8Array([10, 1, 2, 3]),
  )
  // PAA: PDN type IPv4 + address
  const paa = concat(new Uint8Array([1]), new Uint8Array(UE_IP))

  const ies = concat(
    v2Ie(1, imsi),
    v2Ie(75, mei),
    v2Ie(76, msisdn),
    v2Ie(71, apn),
    v2Ie(87, fteid),
    v2Ie(79, paa),
  )

  // Header: ver=2, T=1 (TEID present), msg=32, length, TEID=0, seq
  const hdr = new Uint8Array(12)
  hdr[0] = 0x48 // version 2, T=1
  hdr[1] = 32 // Create Session Request
  const msgLen = 8 + ies.length // after first 4 bytes: TEID(4)+seq(4) + IEs — TS: length excludes first 4
  hdr[2] = (msgLen >> 8) & 0xff
  hdr[3] = msgLen & 0xff
  // TEID = 0 (sentinel)
  hdr[8] = 0x00
  hdr[9] = 0x01
  hdr[10] = 0x02
  hdr[11] = 0x00 // seq + spare
  return concat(hdr, ies)
}

/** Minimal IPv4 UDP inner packet with SIP-looking payload canary. */
function buildInnerIpv4Sip(srcIp: readonly number[], sipCanary: string): Uint8Array {
  const sip = new TextEncoder().encode(
    `INVITE sip:user@example.com SIP/2.0\r\nCall-ID: ${sipCanary}\r\n\r\n`,
  )
  const ipLen = 20 + 8 + sip.length
  const pkt = new Uint8Array(ipLen)
  pkt[0] = 0x45
  pkt[2] = (ipLen >> 8) & 0xff
  pkt[3] = ipLen & 0xff
  pkt[8] = 64
  pkt[9] = 17 // UDP
  pkt.set(srcIp, 12)
  pkt.set([10, 0, 0, 1], 16)
  const udp = 20
  pkt[udp] = 0x13
  pkt[udp + 1] = 0xc4 // 5060
  pkt[udp + 2] = 0x13
  pkt[udp + 3] = 0xc4
  const udpLen = 8 + sip.length
  pkt[udp + 4] = (udpLen >> 8) & 0xff
  pkt[udp + 5] = udpLen & 0xff
  pkt.set(sip, udp + 8)
  return pkt
}

function buildGtpU(teid: number, tpdu: Uint8Array): Uint8Array {
  const hdr = new Uint8Array(8)
  hdr[0] = 0x30 // GTPv1, PT=1
  hdr[1] = 0xff // G-PDU
  hdr[2] = (tpdu.length >> 8) & 0xff
  hdr[3] = tpdu.length & 0xff
  hdr.set(u32be(teid), 4)
  return concat(hdr, tpdu)
}

describe('T26 registry', () => {
  it('registers GTP handler, mobile-core family, engine version', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('gtp')
    expect(familyForProtocol('gtp-u').familyId).toBe('mobile-core')
    expect(familyForProtocol('gtpv2-c').familyId).toBe('mobile-core')
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
  })
})

describe('T26 GTPv2-C + GTP-U consistency', () => {
  it('maps TEID and UE IP consistently; redacts IMSI/IMEI/MSISDN canaries', () => {
    const mapping = new SessionMapping(undefined, { seed: 't26-gtp-session' })
    const csr = buildCreateSessionRequest()
    const frameC = buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], GTP_C_UDP_PORT, GTP_C_UDP_PORT, csr)
    const rC = sanitizePacket(packetInput(frameC), DIAGNOSTIC_POLICY, mapping)
    expect(rC.coverage.some((c) => c.protocol === 'gtpv2-c')).toBe(true)
    const outC = applyPatches(frameC, rC)
    const textC = new TextDecoder('latin1').decode(outC)
    expect(textC.includes(IMSI_CANARY)).toBe(false)
    expect(textC.includes(IMEI_CANARY)).toBe(false)
    expect(textC.includes(MSISDN_DIGITS)).toBe(false)
    // TBCD wire canaries must not survive as encoded nibbles either
    const imsiWire = encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!
    expect(indexOfSubarray(outC, imsiWire)).toBe(-1)

    // F-TEID IE carries receive endpoint 10.1.2.3 — same namespace as GTP-U to that dst.
    const teidCanon = teidCanonicalKey(F_TEID_VAL, { receiveEndpoint: '10.1.2.3', plane: 'u' })
    const teidAlias = Number(mapping.map('teid', teidCanon)) >>> 0
    expect(teidAlias).not.toBe(F_TEID_VAL)
    expect(teidAlias).not.toBe(0)
    // Distinct receive endpoints must not share the alias (V17).
    const otherEndpointAlias = Number(
      mapping.map('teid', teidCanonicalKey(F_TEID_VAL, { receiveEndpoint: '10.9.9.9', plane: 'u' })),
    ) >>> 0
    expect(otherEndpointAlias).not.toBe(teidAlias)

    const ueCanon = UE_IP.join('.')
    const ueAlias = mapping.map('ipv4', ueCanon)
    expect(ueAlias).not.toBe(ueCanon)

    const sipCanary = 'gtp-sip-callid-CANARY-99'
    const tpdu = buildInnerIpv4Sip(UE_IP, sipCanary)
    const gtpU = buildGtpU(F_TEID_VAL, tpdu)
    // Outer dst = F-TEID receive endpoint so header TEID shares the scoped alias.
    const frameU = buildEthIpUdp([10, 1, 2, 4], [10, 1, 2, 3], GTP_U_UDP_PORT, GTP_U_UDP_PORT, gtpU)
    const rU = sanitizePacket(packetInput(frameU), DIAGNOSTIC_POLICY, mapping)
    expect(rU.coverage.some((c) => c.protocol === 'gtp-u')).toBe(true)
    const outU = applyPatches(frameU, rU)
    const textU = new TextDecoder('latin1').decode(outU)
    expect(textU.includes(sipCanary)).toBe(false)

    // GTP-U header TEID at UDP payload + 4
    const gtpPayloadOff = 14 + 20 + 8
    const teidOut =
      ((outU[gtpPayloadOff + 4]! << 24)
        | (outU[gtpPayloadOff + 5]! << 16)
        | (outU[gtpPayloadOff + 6]! << 8)
        | outU[gtpPayloadOff + 7]!) >>> 0
    expect(teidOut).toBe(teidAlias)

    // Inner IPv4 src after GTP header (8) + IPv4 src at +12
    const innerIpOff = gtpPayloadOff + 8 + 12
    const innerSrc = `${outU[innerIpOff]}.${outU[innerIpOff + 1]}.${outU[innerIpOff + 2]}.${outU[innerIpOff + 3]}`
    expect(innerSrc).toBe(ueAlias)
    expect(innerSrc).not.toBe(ueCanon)
  })

  it('masks unstructured GTP-U PDU with explicit gap', () => {
    const junk = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    const gtpU = buildGtpU(0x11223344, junk)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], GTP_U_UDP_PORT, GTP_U_UDP_PORT, gtpU)
    const mapping = new SessionMapping(undefined, { seed: 't26-unstructured' })
    const r = sanitizePacket(packetInput(frame), HIGH_PRIVACY_POLICY, mapping)
    expect(r.coverage.some((c) => c.protocol === 'gtp-u-unstructured')).toBe(true)
    expect(r.issues.some((i) => i.includes('unstructured'))).toBe(true)
    const out = applyPatches(frame, r)
    expect([...out.subarray(14 + 20 + 8 + 8, 14 + 20 + 8 + 8 + junk.length)]).not.toEqual([...junk])
  })

  it('preserves TEID zero sentinel', () => {
    const mapping = new SessionMapping(undefined, { seed: 't26-teid0' })
    const hdr = new Uint8Array(8)
    hdr[0] = 0x30
    hdr[1] = 1 // Echo Request
    hdr[2] = 0
    hdr[3] = 0
    // TEID = 0
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], GTP_U_UDP_PORT, GTP_U_UDP_PORT, hdr)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    const off = 14 + 20 + 8 + 4
    expect(out[off]).toBe(0)
    expect(out[off + 1]).toBe(0)
    expect(out[off + 2]).toBe(0)
    expect(out[off + 3]).toBe(0)
  })

  it('PCO maps DNS IPv4 and masks PAP password (T26.spec PCO subcodec)', () => {
    const papSecret = new TextEncoder().encode('GTP-PAP-SECRET-CANARY')
    const papBody = concat(new Uint8Array([1, papSecret.length]), papSecret)
    const dnsIp = new Uint8Array([8, 8, 8, 8])
    const pco = concat(
      new Uint8Array([0x80]), // Configuration protocol (PPP)
      new Uint8Array([0xc0, 0x23, papBody.length]),
      papBody,
      new Uint8Array([0x00, 0x0d, 0x04]),
      dnsIp,
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
    const mapping = new SessionMapping(undefined, { seed: 't26-pco' })
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('GTP-PAP-SECRET-CANARY')).toBe(false)
    expect(r.coverage.some((c) => c.protocol === 'gtp-pco-auth')).toBe(true)
    expect(r.coverage.some((c) => c.protocol === 'gtp-pco-ip')).toBe(true)
    const dnsCanon = '8.8.8.8'
    expect(text.includes(dnsCanon)).toBe(false)
    expect(mapping.map('ipv4', dnsCanon)).not.toBe(dnsCanon)
  })

  it('walks GTPv1-C TV IMSI via v1 walker (T26.spec v1/v2 split)', () => {
    const imsi = encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!
    const ies = concat(new Uint8Array([2]), imsi)
    const hdr = new Uint8Array(8)
    hdr[0] = 0x32
    hdr[1] = 16 // Create PDP Request
    hdr[2] = (ies.length >> 8) & 0xff
    hdr[3] = ies.length & 0xff
    const pdu = concat(hdr, ies)
    const frame = buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], GTP_C_UDP_PORT, GTP_C_UDP_PORT, pdu)
    const mapping = new SessionMapping(undefined, { seed: 't26-v1-imsi' })
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(r.coverage.some((c) => c.protocol === 'gtpv1-c')).toBe(true)
    expect(r.coverage.some((c) => c.protocol === 'gtpv2-imsi')).toBe(false)
    const out = applyPatches(frame, r)
    expect(new TextDecoder('latin1').decode(out).includes(IMSI_CANARY)).toBe(false)
  })

  it('sanitizes GTPv2 piggybacked messages in one UDP datagram (T26.spec piggyback)', () => {
    const imsi2 = encodeTbcd('262019998887766', 8, TBCD_GSM)!
    const msg2Ies = v2Ie(1, imsi2)
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
    hdr1[0] = 0x58 // v2 + T + P piggyback
    hdr1[1] = 33 // Create Session Response
    const msg1Len = 8 + msg1Ies.length
    hdr1[2] = (msg1Len >> 8) & 0xff
    hdr1[3] = msg1Len & 0xff
    const msg1 = concat(hdr1, msg1Ies)
    const piggy = concat(msg1, msg2)

    const frame = buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], GTP_C_UDP_PORT, GTP_C_UDP_PORT, piggy)
    const mapping = new SessionMapping(undefined, { seed: 't26-piggyback' })
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(r.issues?.some((i) => i === 'gtpv2-piggyback')).toBe(true)
    expect(r.coverage.some((c) => c.protocol === 'gtpv2-piggyback')).toBe(true)
    expect(r.coverage.some((c) => c.protocol === 'gtpv2-imsi')).toBe(true)
    const out = applyPatches(frame, r)
    expect(new TextDecoder('latin1').decode(out).includes('262019998887766')).toBe(false)
  })

  it('decodes GTP-U Ethernet T-PDU via linked Ethernet child (T26.spec Ethernet PDU)', () => {
    const sipCanary = 'gtp-eth-inner-sip-CANARY'
    const innerIp = buildInnerIpv4Sip(UE_IP, sipCanary)
    const eth = new Uint8Array(14 + innerIp.length)
    eth.set([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], 0)
    eth.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
    eth[12] = 0x08
    eth[13] = 0x00
    eth.set(innerIp, 14)
    const gtpU = buildGtpU(F_TEID_VAL, eth)
    const frame = buildEthIpUdp([10, 1, 2, 4], [10, 1, 2, 3], GTP_U_UDP_PORT, GTP_U_UDP_PORT, gtpU)
    const mapping = new SessionMapping(undefined, { seed: 't26-eth-tpdu' })
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(r.coverage.some((c) => c.protocol === 'gtp-u-ethernet')).toBe(true)
    const out = applyPatches(frame, r)
    expect(new TextDecoder('latin1').decode(out).includes(sipCanary)).toBe(false)
  })

  it('preserves MCC+MNC when Serving Network documents two-digit MNC', () => {
    const mapping = new SessionMapping(undefined, { seed: 't26-imsi-plmn' })
    const imsi = encodeTbcd(IMSI_CANARY, 8, TBCD_GSM)!
    // Serving Network MCC=262 MNC=01 (MNC digit 3 = 0xF)
    const sn = new Uint8Array([0x62, 0xf2, 0x10])
    // IMSI before Serving Network — scan must still discover MNC length.
    const ies = concat(v2Ie(1, imsi), v2Ie(83, sn))
    const hdr = new Uint8Array(12)
    hdr[0] = 0x48
    hdr[1] = 32
    const msgLen = 8 + ies.length
    hdr[2] = (msgLen >> 8) & 0xff
    hdr[3] = msgLen & 0xff
    hdr[8] = 0
    hdr[9] = 1
    hdr[10] = 2
    hdr[11] = 0
    const csr = concat(hdr, ies)
    const frame = buildEthIpUdp([10, 0, 0, 10], [10, 0, 0, 20], GTP_C_UDP_PORT, GTP_C_UDP_PORT, csr)
    const r = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, r)
    expect(new TextDecoder('latin1').decode(out).includes(IMSI_CANARY)).toBe(false)
    const imsiOff = 14 + 20 + 8 + 12 + 4 // eth+ip+udp+gtp hdr + IE hdr
    const mappedTbcd = out.subarray(imsiOff, imsiOff + 8)
    const mappedDigits = decodeTbcd(mappedTbcd, TBCD_GSM)!
    expect(mappedDigits.startsWith('26201')).toBe(true)
    expect(mappedDigits.slice(5)).not.toBe('1234567890')
    expect(mappedDigits).toHaveLength(IMSI_CANARY.length)
  })
})

function indexOfSubarray(hay: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer
    }
    return i
  }
  return -1
}
