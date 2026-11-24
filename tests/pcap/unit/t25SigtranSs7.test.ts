/**
 * T25 — SIGTRAN/SS7: M3UA OPC/DPC point-code, ISUP numbers, MAP auth no-leak.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { sctpCrc32c, writeCrc32cLe } from '../../../src/crypto/crc32c'
import { IPPROTO_SCTP } from '../../../src/pcap/protocols/types'
import { encodeTbcd, TBCD_GSM } from '../../../src/pcap/protocols/application/binproto/tbcd'
import { canonicalizePcapIdentity } from '../../../src/mapping/pcapCanonical'

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

/** Build M3UA Payload Data with one Protocol Data TLV. */
function buildM3uaProtocolData(opc: number, dpc: number, si: number, user: Uint8Array): Uint8Array {
  const pdValueLen = 12 + user.length
  const pdParamLen = 4 + pdValueLen
  const pdPadded = (pdParamLen + 3) & ~3
  const msgLen = 8 + pdPadded
  const out = new Uint8Array(msgLen)
  out[0] = 1 // version
  out[1] = 0
  out[2] = 1 // Transfer
  out[3] = 1 // Payload Data
  out[4] = (msgLen >>> 24) & 0xff
  out[5] = (msgLen >>> 16) & 0xff
  out[6] = (msgLen >>> 8) & 0xff
  out[7] = msgLen & 0xff
  // Protocol Data parameter
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
  out[v + 9] = 0 // NI
  out[v + 10] = 0 // MP
  out[v + 11] = 0 // SLS
  out.set(user, v + 12)
  return out
}

/** ITU ISUP IAM with called party 420123456789. */
function buildIsupIam(calledDigits: string): Uint8Array {
  const tbcd = encodeTbcd(calledDigits, Math.ceil(calledDigits.length / 2), TBCD_GSM)!
  const calledContents = new Uint8Array(2 + tbcd.length)
  calledContents[0] = 0x83 // odd/even + national
  calledContents[1] = 0x10 // E.164
  calledContents.set(tbcd, 2)
  // CIC(2) + type(1) + fixed(5) + ptrCalled(1) + ptrOpt(1) + len(1) + contents
  const out = new Uint8Array(2 + 1 + 5 + 2 + 1 + calledContents.length)
  out[0] = 0x34 // CIC low
  out[1] = 0x12 // CIC high
  out[2] = 0x01 // IAM
  out[3] = 0x00 // nature of connection
  out[4] = 0x00
  out[5] = 0x00 // forward call ind
  out[6] = 0x0a // calling party category
  out[7] = 0x00 // TMR
  out[8] = 2 // pointer to called (skip ptrOpt)
  out[9] = 0 // no optional
  out[10] = calledContents.length
  out.set(calledContents, 11)
  return out
}

/** SCCP UDT with called GT E.164 + TCAP/MAP-ish BER (IMSI + RAND). */
function buildSccpUdtWithMap(gtDigits: string, imsiDigits: string, randCanary: Uint8Array): Uint8Array {
  const gtTbcd = encodeTbcd(gtDigits, Math.ceil(gtDigits.length / 2), TBCD_GSM)!
  // Address: len, AI (GTI=4, no PC, SSN present), SSN, NAI, digits
  const calledAddr = new Uint8Array(1 + 1 + 1 + 1 + gtTbcd.length)
  calledAddr[0] = calledAddr.length - 1
  calledAddr[1] = 0x12 // SSN present (bit1), GTI=4 (bits 2-5 = 0100 → 0x10) → 0x12
  calledAddr[2] = 0x06 // SSN MAP
  calledAddr[3] = 0x04 // NAI international
  calledAddr.set(gtTbcd, 4)

  const callingAddr = new Uint8Array([2, 0x02, 0x07]) // SSN only

  const imsiTbcd = encodeTbcd(imsiDigits, Math.ceil(imsiDigits.length / 2), TBCD_GSM)!
  // BER: SEQUENCE { IMSI OCTET STRING, RAND OCTET STRING }
  const imsiNode = new Uint8Array(2 + imsiTbcd.length)
  imsiNode[0] = 0x04
  imsiNode[1] = imsiTbcd.length
  imsiNode.set(imsiTbcd, 2)
  const randNode = new Uint8Array(2 + randCanary.length)
  randNode[0] = 0x04
  randNode[1] = randCanary.length
  randNode.set(randCanary, 2)
  const seqInner = imsiNode.length + randNode.length
  const tcap = new Uint8Array(2 + seqInner)
  tcap[0] = 0x30
  tcap[1] = seqInner
  tcap.set(imsiNode, 2)
  tcap.set(randNode, 2 + imsiNode.length)

  // UDT layout: type, class, ptrCalled, ptrCalling, ptrData, then parameters in order
  // ptrCalled at offset+2: value = distance to calledAddr length byte
  // After 5-byte header, place called, calling, data
  const header = 5
  const dataParam = new Uint8Array(1 + tcap.length)
  dataParam[0] = tcap.length
  dataParam.set(tcap, 1)

  const body = new Uint8Array(calledAddr.length + callingAddr.length + dataParam.length)
  body.set(calledAddr, 0)
  body.set(callingAddr, calledAddr.length)
  body.set(dataParam, calledAddr.length + callingAddr.length)

  const out = new Uint8Array(header + body.length)
  out[0] = 0x09 // UDT
  out[1] = 0x81 // class 1
  // Pointers relative to the pointer octet
  out[2] = 3 // called starts at out[2]+3 = out[5]
  out[3] = 3 + calledAddr.length - 1 // calling: out[3] + ptr = out[5] + calledAddr.length
  // out[3] + ptrCalling = 5 + calledAddr.length → ptrCalling = 5 + calledAddr.length - 3 = 2 + calledAddr.length
  out[3] = 2 + calledAddr.length
  // out[4] + ptrData = 5 + calledAddr.length + callingAddr.length
  out[4] = 1 + calledAddr.length + callingAddr.length
  out.set(body, 5)
  return out
}

describe('T25 registry', () => {
  it('registers M3UA/SCCP/ISUP families and bumps engine version', () => {
    expect(familyForProtocol('m3ua').familyId).toBe('mobile-core')
    expect(familyForProtocol('sccp').familyId).toBe('mobile-core')
    expect(familyForProtocol('isup').familyId).toBe('mobile-core')
    expect(familyForProtocol('map-imsi').familyId).toBe('mobile-core')
    expect(PCAP_ENGINE_VERSION).toBe('2.35.0')
  })

  it('canonicalizes point-code width-stably', () => {
    expect(canonicalizePcapIdentity('point-code', 'pc/14/1234')).toBe('pc/14/1234')
    expect(canonicalizePcapIdentity('point-code', 'pc/24/999')).toBe('pc/24/999')
    expect(canonicalizePcapIdentity('point-code', 'pc/14/99999')).toBeNull()
    const m = new SessionMapping(undefined, { seed: 't25-pc' })
    const a = m.map('point-code', 'pc/24/100')
    const b = m.map('point-code', 'pc/24/100')
    expect(a).toBe(b)
    expect(a).toMatch(/^pc\/24\/\d+$/)
    expect(a).not.toBe('pc/24/100')
  })
})

describe('T25 M3UA + ISUP', () => {
  it('maps OPC/DPC and called number; never leaks canary digits', () => {
    const called = '420123456789'
    const isup = buildIsupIam(called)
    const opc = 0x001122
    const dpc = 0x003344
    const m3ua = buildM3uaProtocolData(opc, dpc, 5, isup)
    const sctp = buildDataChunk(2905, 2905, 3, m3ua)
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 't25-isup' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, result)

    expect(Buffer.from(out).includes(Buffer.from(called))).toBe(false)
    // Original OPC/DPC bytes must not remain in Protocol Data
    const opcBytes = Buffer.from([(opc >>> 24) & 0xff, (opc >>> 16) & 0xff, (opc >>> 8) & 0xff, opc & 0xff])
    const dpcBytes = Buffer.from([(dpc >>> 24) & 0xff, (dpc >>> 16) & 0xff, (dpc >>> 8) & 0xff, dpc & 0xff])
    // Search only in SCTP user payload region (skip Ethernet/IP)
    const payload = out.subarray(34)
    expect(Buffer.from(payload).includes(opcBytes)).toBe(false)
    expect(Buffer.from(payload).includes(dpcBytes)).toBe(false)

    const protocols = result.coverage.map((c) => c.protocol)
    expect(protocols).toContain('m3ua')
    expect(protocols).toContain('isup')
    expect(protocols).toContain('isup-number')

    // Same OPC maps consistently across two packets
    const frame2 = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], buildDataChunk(2905, 2905, 3, m3ua))
    const result2 = sanitizePacket(packetInput(frame2), DIAGNOSTIC_POLICY, mapping)
    const out2 = applyPatches(frame2, result2)
    // OPC alias bytes equal in both outputs (at M3UA PD value offset within SCTP user)
    // SCTP hdr 12 + DATA fixed 16 = 28; M3UA hdr 8 + TLV hdr 4 = 12 → OPC at 28+12=40 into sctp
    const opcOff = 34 + 28 + 12
    expect(out.subarray(opcOff, opcOff + 4)).toEqual(out2.subarray(opcOff, opcOff + 4))
  })
})

/** SCCP XUDT (single segment, no optional part) — same pointer layout as UDT with 6-byte fixed header. */
function buildSccpXudtSingle(gtDigits: string, imsiDigits: string, randCanary: Uint8Array): Uint8Array {
  const udt = buildSccpUdtWithMap(gtDigits, imsiDigits, randCanary)
  const out = udt.slice()
  out[0] = 0x11 // XUDT
  // Insert optional-part pointer (0 = none) after data pointer: shift body by 1 octet.
  const header = 6
  const body = udt.subarray(5)
  const expanded = new Uint8Array(header + body.length)
  expanded[0] = 0x11
  expanded[1] = udt[1]!
  expanded[2] = udt[2]! + 1 // called ptr +1 (extra header octet before variable part)
  expanded[3] = udt[3]! + 1
  expanded[4] = udt[4]! + 1
  expanded[5] = 0 // no optional part
  expanded.set(body, header)
  return expanded
}

/** E.214 GT (GTI=3, NP=6) — must map opaque-id namespace, not sip-phone / IMSI. */
function buildSccpUdtE214Gt(e214Digits: string): Uint8Array {
  const gtTbcd = encodeTbcd(e214Digits, Math.ceil(e214Digits.length / 2), TBCD_GSM)!
  const calledAddr = new Uint8Array(1 + 1 + 1 + 1 + gtTbcd.length)
  calledAddr[0] = calledAddr.length - 1
  calledAddr[1] = 0x0e // GTI=3 (0011), SSN present
  calledAddr[2] = 0x06 // SSN MAP
  calledAddr[3] = 0x60 // NP=6 (E.214), ES=0
  calledAddr.set(gtTbcd, 4)
  const callingAddr = new Uint8Array([2, 0x02, 0x07])
  const tcap = new Uint8Array([0x30, 0x00]) // empty TCAP shell
  const dataParam = new Uint8Array(1 + tcap.length)
  dataParam[0] = tcap.length
  dataParam.set(tcap, 1)
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

describe('T25 SCCP spec slices (2026-10-17)', () => {
  it('maps E.214 GT digits in opaque-id namespace (not sip-phone)', () => {
    const e214 = '262011234567890'
    const sccp = buildSccpUdtE214Gt(e214)
    const m3ua = buildM3uaProtocolData(0x10, 0x20, 3, sccp)
    const sctp = buildDataChunk(2905, 2905, 3, m3ua)
    const frame = buildEthIpSctp([10, 2, 0, 1], [10, 2, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 't25-e214-gt' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, result)
    expect(Buffer.from(out).toString('latin1')).not.toContain(e214)
    expect(result.coverage.some((c) => c.protocol === 'sccp-gt-e214')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'sccp-gt-e164')).toBe(false)
    const phoneAlias = mapping.map('sip-phone', `+${e214}`)
    const gtAlias = mapping.map('opaque-id', `gt214:${e214}`)
    expect(gtAlias).not.toBe(phoneAlias)
  })

  it('parses single-segment XUDT like UDT; multi-segment stays requires-reassembly', () => {
    const rand = new Uint8Array(16).fill(0xab)
    const imsi = '230010123456789'
    const gt = '420987654321'
    const xudt = buildSccpXudtSingle(gt, imsi, rand)
    const m3ua = buildM3uaProtocolData(0x10, 0x20, 3, xudt)
    const sctp = buildDataChunk(2905, 2905, 3, m3ua)
    const frame = buildEthIpSctp([10, 3, 0, 1], [10, 3, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 't25-xudt-single' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, result)
    expect(Buffer.from(out).includes(rand)).toBe(false)
    expect(result.coverage.some((c) => c.protocol === 'sccp-gt-e164')).toBe(true)
    expect(result.coverage.some((c) => c.status === 'requires-reassembly')).toBe(false)

    // Multi-segment XUDT: append segmentation optional part (remaining>0).
    const segOpt = new Uint8Array([0x10, 0x02, 0x02, 0x01])
    const segmented = new Uint8Array(xudt.length + segOpt.length)
    segmented.set(xudt, 0)
    segmented.set(segOpt, xudt.length)
    segmented[5] = xudt.length - 6 // optional part starts at end of former XUDT body
    const m3ua2 = buildM3uaProtocolData(0x10, 0x20, 3, segmented)
    const frame2 = buildEthIpSctp([10, 3, 0, 3], [10, 3, 0, 4], buildDataChunk(2905, 2905, 3, m3ua2))
    const result2 = sanitizePacket(packetInput(frame2), DIAGNOSTIC_POLICY, mapping)
    expect(result2.coverage.some((c) => c.status === 'requires-reassembly')).toBe(true)
    expect(result2.issues.some((i) => i.includes('reassembly'))).toBe(true)
  })
})

/** M2PA Payload Data (RFC 4165) with ANSI DPC/OPC + masked protocol data. */
function buildM2paPayloadData(dpc: number, opc: number, protoCanary: Uint8Array): Uint8Array {
  const bodyLen = 4 + 7 + protoCanary.length
  const msgLen = 10 + bodyLen
  const out = new Uint8Array(msgLen)
  out[0] = 1
  out[2] = 0
  out[3] = 11
  out[4] = 0
  out[5] = 1
  out[6] = (msgLen >>> 24) & 0xff
  out[7] = (msgLen >>> 16) & 0xff
  out[8] = (msgLen >>> 8) & 0xff
  out[9] = msgLen & 0xff
  const rl = 14
  out[rl] = (dpc >>> 16) & 0xff
  out[rl + 1] = (dpc >>> 8) & 0xff
  out[rl + 2] = dpc & 0xff
  out[rl + 3] = (opc >>> 16) & 0xff
  out[rl + 4] = (opc >>> 8) & 0xff
  out[rl + 5] = opc & 0xff
  out[rl + 6] = 0x05 // SLS
  out.set(protoCanary, 21)
  return out
}

describe('T25 M2PA baseline (T25.spec M2PA/ANSI PC)', () => {
  it('maps ANSI DPC/OPC and masks protocol data canary', () => {
    const dpc = 0x010203
    const opc = 0x040506
    const proto = new TextEncoder().encode('M2PA-PROTO-CANARY-SS7')
    const m2pa = buildM2paPayloadData(dpc, opc, proto)
    const sctp = buildDataChunk(2905, 2905, 5, m2pa)
    const frame = buildEthIpSctp([10, 4, 0, 1], [10, 4, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 't25-m2pa' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, result)
    expect(Buffer.from(out).includes(proto)).toBe(false)
    expect(result.coverage.some((c) => c.protocol === 'm2pa-ansi-pc')).toBe(true)
    const dpcBytes = Buffer.from([(dpc >>> 16) & 0xff, (dpc >>> 8) & 0xff, dpc & 0xff])
    const opcBytes = Buffer.from([(opc >>> 16) & 0xff, (opc >>> 8) & 0xff, opc & 0xff])
    const payload = out.subarray(34)
    expect(Buffer.from(payload).includes(dpcBytes)).toBe(false)
    expect(Buffer.from(payload).includes(opcBytes)).toBe(false)
    expect(mapping.map('point-code', `pc/24/${dpc}`)).not.toBe(`pc/24/${dpc}`)
  })
})

describe('T25 SCCP + TCAP/MAP', () => {
  it('maps IMSI and masks RAND auth canary', () => {
    const randCanary = new Uint8Array([
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ])
    const imsi = '230010123456789'
    const gt = '420987654321'
    const sccp = buildSccpUdtWithMap(gt, imsi, randCanary)
    const m3ua = buildM3uaProtocolData(0x10, 0x20, 3, sccp)
    const sctp = buildDataChunk(2905, 2905, 3, m3ua)
    const frame = buildEthIpSctp([10, 1, 0, 1], [10, 1, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 't25-map' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, result)

    expect(Buffer.from(out).includes(Buffer.from(randCanary))).toBe(false)
    expect(Buffer.from(out).toString('latin1')).not.toContain(imsi)
    expect(Buffer.from(out).toString('latin1')).not.toContain(gt)

    const protocols = result.coverage.map((c) => c.protocol)
    expect(protocols).toContain('sccp')
    expect(protocols).toContain('tcap')
    expect(protocols.some((p) => p === 'map-imsi' || p === 'map-secret')).toBe(true)
  })
})
