/**
 * T38 — routing / first-hop: auth canaries (OSPF, RIP, HSRP) + TCP MD5 + registry.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp, buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { buildProtocolSupportMatrix } from '../../../src/pcap/docs/protocolSupportMatrix'

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

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

/** Ethernet + IPv4 + raw IP payload (no L4). */
function buildEthIpProto(srcIp: number[], dstIp: number[], proto: number, payload: Uint8Array): Uint8Array {
  const total = 14 + 20 + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = proto
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  buf.set(payload, 34)
  return buf
}

/** TCP with options (data offset includes options). */
function buildEthIpTcpOpts(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  options: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  const pad = (4 - (options.length % 4)) % 4
  const tcpHdr = 20 + options.length + pad
  const total = 14 + 20 + tcpHdr + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + tcpHdr + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = 6
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  const tcp = 34
  buf[tcp] = (srcPort >> 8) & 0xff
  buf[tcp + 1] = srcPort & 0xff
  buf[tcp + 2] = (dstPort >> 8) & 0xff
  buf[tcp + 3] = dstPort & 0xff
  buf[tcp + 12] = ((tcpHdr / 4) << 4)
  buf[tcp + 13] = 0x10
  if (options.length) buf.set(options, tcp + 20)
  buf.set(payload, tcp + tcpHdr)
  return buf
}

describe('T38 registry', () => {
  it('registers routing app handlers, family, matrix rows, and engine 2.11.0', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(expect.arrayContaining(['bgp', 'ldp', 'rip', 'bfd', 'hsrp']))
    expect(familyForProtocol('ospf').familyId).toBe('routing')
    expect(familyForProtocol('bgp').familyId).toBe('routing')
    expect(familyForProtocol('hsrp').familyId).toBe('routing')
    expect(familyForProtocol('tcp-md5').familyId).toBe('routing')
    expect(PCAP_ENGINE_VERSION).toBe('2.35.0')
    const matrixIds = buildProtocolSupportMatrix().map((r) => r.id)
    expect(matrixIds).toEqual(
      expect.arrayContaining(['ip:ospf', 'ip:eigrp', 'ip:pim', 'ip:igmp', 'llc:isis', 'app:bgp', 'app:rip', 'app:hsrp']),
    )
  })
})

describe('T38 OSPF auth', () => {
  it('masks simple-password auth and does not leak canary', () => {
    const auth = new TextEncoder().encode('SECRETo!') // 8 bytes
    const ospf = new Uint8Array(24)
    ospf[0] = 2 // version
    ospf[1] = 1 // Hello
    ospf[2] = 0
    ospf[3] = 24 // length
    ospf.set([10, 1, 2, 3], 4) // router id
    ospf.set([0, 0, 0, 1], 8) // area
    ospf[14] = 0
    ospf[15] = 1 // AuType simple
    ospf.set(auth, 16)
    const frame = buildEthIpProto([192, 0, 2, 1], [224, 0, 0, 5], 89, ospf)
    const mapping = new SessionMapping(undefined, { seed: 't38-ospf' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'ospf-auth')).toBe(true)
    const out = applyPatches(frame, result)
    expect(latin1(out).includes('SECRETo!')).toBe(false)
    // Auth region must differ from canary
    expect([...out.subarray(34 + 16, 34 + 24)]).not.toEqual([...auth])
  })
})

describe('T38 RIP auth', () => {
  it('masks RIPv2 auth entry with default-style password', () => {
    const payload = new Uint8Array(4 + 20)
    payload[0] = 2 // response
    payload[1] = 2 // version
    // Auth entry: AFI 0xffff
    payload[4] = 0xff
    payload[5] = 0xff
    payload[6] = 0
    payload[7] = 2 // auth type simple
    const pw = new TextEncoder().encode('cisco\0\0\0\0\0\0\0\0\0\0\0') // 16 bytes
    payload.set(pw.subarray(0, 16), 8)
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 520, 520, payload)
    const mapping = new SessionMapping(undefined, { seed: 't38-rip' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'rip-auth')).toBe(true)
    const out = applyPatches(frame, result)
    expect(latin1(out).includes('cisco')).toBe(false)
  })
})

describe('T38 HSRP auth', () => {
  it('masks HSRP v1 auth string and maps virtual IP', () => {
    const payload = new Uint8Array(20)
    payload[0] = 0 // version
    payload[1] = 0 // hello
    payload[2] = 16 // state active
    payload[3] = 3 // hellotime
    payload[4] = 10 // holdtime
    payload[5] = 100 // priority
    payload[6] = 1 // group
    const auth = new TextEncoder().encode('cisco\0\0\0')
    payload.set(auth, 8)
    payload.set([10, 20, 30, 40], 16) // VIP
    const frame = buildEthIpUdp([192, 0, 2, 1], [224, 0, 0, 2], 1985, 1985, payload)
    const mapping = new SessionMapping(undefined, { seed: 't38-hsrp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'hsrp-auth')).toBe(true)
    const out = applyPatches(frame, result)
    expect(latin1(out).includes('cisco')).toBe(false)
    const vipOff = 14 + 20 + 8 + 16
    expect([...out.subarray(vipOff, vipOff + 4)]).not.toEqual([10, 20, 30, 40])
  })
})

describe('T38 TCP MD5', () => {
  it('masks TCP option 19 digest independently of BGP body', () => {
    const digest = new TextEncoder().encode('MD5DIGESTCANARY!') // 16
    const opt = new Uint8Array(2 + 16)
    opt[0] = 19
    opt[1] = 18
    opt.set(digest, 2)
    // Minimal BGP KEEPALIVE (19 bytes marker+len+type)
    const keepalive = new Uint8Array(19)
    keepalive.fill(0xff, 0, 16)
    keepalive[16] = 0
    keepalive[17] = 19
    keepalive[18] = 4
    const frame = buildEthIpTcpOpts([192, 0, 2, 1], [192, 0, 2, 2], 179, 179, opt, keepalive)
    const mapping = new SessionMapping(undefined, { seed: 't38-md5' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'tcp-md5')).toBe(true)
    const out = applyPatches(frame, result)
    expect(latin1(out).includes('MD5DIGESTCANARY!')).toBe(false)
  })
})

describe('T38 IS-IS auth', () => {
  it('masks cleartext auth TLV 10', () => {
    const canary = new TextEncoder().encode('ISIS-AUTH-CANARY!!')
    const pdu = new Uint8Array(8 + 2 + canary.length)
    pdu[0] = 0x83 // IS-IS discriminator
    pdu[8] = 10 // Auth TLV
    pdu[9] = canary.length
    pdu.set(canary, 10)
    const llc = new Uint8Array(3 + pdu.length)
    llc[0] = 0xfe
    llc[1] = 0xfe
    llc[2] = 0x03
    llc.set(pdu, 3)
    const frame = new Uint8Array(14 + llc.length)
    frame.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
    frame.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
    frame[12] = 0
    frame[13] = llc.length
    frame.set(llc, 14)
    const mapping = new SessionMapping(undefined, { seed: 't38-isis' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'isis-auth')).toBe(true)
    const out = applyPatches(frame, result)
    expect(latin1(out).includes('ISIS-AUTH-CANARY')).toBe(false)
  })
})

describe('T38 BGP OPEN', () => {
  it('maps BGP Identifier as router-id (not left as original bytes)', () => {
    const open = new Uint8Array(19 + 10)
    open.fill(0xff, 0, 16)
    open[16] = 0
    open[17] = 29 // length
    open[18] = 1 // OPEN
    open[19] = 4 // version
    open[20] = 0xfd
    open[21] = 0xe8 // AS 65000
    open[22] = 0
    open[23] = 90 // hold
    open.set([1, 2, 3, 4], 24) // BGP ID
    open[28] = 0 // opt len
    const frame = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 179, 179, 1, open)
    const mapping = new SessionMapping(undefined, { seed: 't38-bgp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'bgp' || c.protocol === 'bgp-open')).toBe(true)
    const out = applyPatches(frame, result)
    const idOff = 14 + 20 + 20 + 24
    expect([...out.subarray(idOff, idOff + 4)]).not.toEqual([1, 2, 3, 4])
  })
})
