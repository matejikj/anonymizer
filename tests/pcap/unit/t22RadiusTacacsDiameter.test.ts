/**
 * T22 — RADIUS / TACACS+ / Diameter AAA sanitizers.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp, buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { UNSUPPORTED_PROTOCOL_NAMES } from '../../../src/pcap/sanitize/unsupportedIdentification'

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

function radiusAccessRequest(user: string, passwordCanary: string): Uint8Array {
  const userBytes = new TextEncoder().encode(user)
  const passBytes = new TextEncoder().encode(passwordCanary)
  const attrsLen = 2 + userBytes.length + 2 + passBytes.length
  const pkt = new Uint8Array(20 + attrsLen)
  pkt[0] = 1 // Access-Request
  pkt[1] = 7 // id
  const total = 20 + attrsLen
  pkt[2] = (total >> 8) & 0xff
  pkt[3] = total & 0xff
  // Authenticator canary
  for (let i = 0; i < 16; i++) pkt[4 + i] = 0xa0 + i
  let o = 20
  pkt[o] = 1 // User-Name
  pkt[o + 1] = 2 + userBytes.length
  pkt.set(userBytes, o + 2)
  o += 2 + userBytes.length
  pkt[o] = 2 // User-Password
  pkt[o + 1] = 2 + passBytes.length
  pkt.set(passBytes, o + 2)
  return pkt
}

describe('T22 registry', () => {
  it('registers AAA handlers and promotes off unsupported', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(expect.arrayContaining(['radius', 'tacacs', 'diameter']))
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('radius')
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('diameter')
    expect(familyForProtocol('radius').familyId).toBe('aaa')
    expect(familyForProtocol('tacacs').familyId).toBe('aaa')
    expect(familyForProtocol('diameter').familyId).toBe('aaa')
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
  })
})

describe('T22 RADIUS', () => {
  it('maps User-Name and masks Authenticator and User-Password', () => {
    const payload = radiusAccessRequest('alice@corp.example', 'PASS-CANARY-99')
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1812, 1812, payload)
    const mapping = new SessionMapping(undefined, { seed: 't22-radius' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'radius')).toBe(true)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('PASS-CANARY-99')).toBe(false)
    expect(text.includes('alice@corp.example')).toBe(false)
    // Authenticator bytes changed
    expect(out[14 + 20 + 8 + 4]).not.toBe(0xa0)
  })

  it('keeps Acct-Session-Id correlation via opaque alias', () => {
    const sid = new TextEncoder().encode('sess-canary-001')
    const pkt = new Uint8Array(20 + 2 + sid.length)
    pkt[0] = 4 // Accounting-Request
    pkt[1] = 1
    pkt[2] = 0
    pkt[3] = pkt.length
    pkt[20] = 44
    pkt[21] = 2 + sid.length
    pkt.set(sid, 22)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1813, 1813, pkt)
    const mapping = new SessionMapping(undefined, { seed: 't22-acct' })
    const r1 = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out1 = applyPatches(frame, r1)
    const r2 = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out2 = applyPatches(frame, r2)
    expect([...out1.subarray(14 + 20 + 8 + 22, 14 + 20 + 8 + 22 + sid.length)]).toEqual(
      [...out2.subarray(14 + 20 + 8 + 22, 14 + 20 + 8 + 22 + sid.length)],
    )
    expect(new TextDecoder('latin1').decode(out1).includes('sess-canary-001')).toBe(false)
  })
})

describe('T22 TACACS+', () => {
  it('masks obfuscated body in both levels', () => {
    const body = new Uint8Array(16)
    for (let i = 0; i < 16; i++) body[i] = 0x5a
    const pkt = new Uint8Array(12 + body.length)
    pkt[0] = 0xc0 // major 12
    pkt[1] = 1 // authen
    pkt[2] = 1 // seq
    pkt[3] = 0 // encrypted (no UNENCRYPTED flag)
    pkt[4] = 0x11
    pkt[5] = 0x22
    pkt[6] = 0x33
    pkt[7] = 0x44 // session id
    const bl = body.length
    pkt[8] = (bl >>> 24) & 0xff
    pkt[9] = (bl >>> 16) & 0xff
    pkt[10] = (bl >>> 8) & 0xff
    pkt[11] = bl & 0xff
    pkt.set(body, 12)
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 49_000, 49, 1, pkt)
    for (const policy of [DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY]) {
      const mapping = new SessionMapping(undefined, { seed: 't22-tacacs' })
      const result = sanitizePacket(packetInput(frame), policy, mapping)
      expect(result.coverage.some((c) => c.protocol === 'tacacs')).toBe(true)
      expect(result.issues.some((i) => i.includes('obfuscated'))).toBe(true)
      const out = applyPatches(frame, result)
      const payloadOff = 14 + 20 + 20
      expect(out[payloadOff + 12]).not.toBe(0x5a)
    }
  })
})

describe('T22 Diameter', () => {
  it('maps Origin-Host and masks unknown AVP / auth material', () => {
    const host = new TextEncoder().encode('pcrf.example.com')
    // AVP Origin-Host 264: code(4)+flags(1)+len(3)+data, padded
    const avpLen = 8 + host.length
    const pad = (4 - (avpLen % 4)) % 4
    const avp = new Uint8Array(avpLen + pad)
    avp[0] = 0
    avp[1] = 0
    avp[2] = 1
    avp[3] = 0x08 // 264
    avp[4] = 0x40 // M
    avp[5] = (avpLen >> 16) & 0xff
    avp[6] = (avpLen >> 8) & 0xff
    avp[7] = avpLen & 0xff
    avp.set(host, 8)
    if (pad) avp[avpLen] = 0xca // canary padding

    // Auth-Info style AVP 1413 — mask
    const auth = new Uint8Array(12)
    auth[0] = 0
    auth[1] = 0
    auth[2] = 0x05
    auth[3] = 0x85 // 1413
    auth[4] = 0x40
    auth[5] = 0
    auth[6] = 0
    auth[7] = 12
    auth[8] = 0xde
    auth[9] = 0xad
    auth[10] = 0xbe
    auth[11] = 0xef

    const msgLen = 20 + avp.length + auth.length
    const msg = new Uint8Array(msgLen)
    msg[0] = 1
    msg[1] = (msgLen >> 16) & 0xff
    msg[2] = (msgLen >> 8) & 0xff
    msg[3] = msgLen & 0xff
    msg[5] = 0x01 // cmd code high — CCR-ish
    msg[6] = 0x10
    msg[7] = 0x16
    msg.set(avp, 20)
    msg.set(auth, 20 + avp.length)

    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40_000, 3868, 1, msg)
    const mapping = new SessionMapping(undefined, { seed: 't22-diam' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'diameter')).toBe(true)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('pcrf.example.com')).toBe(false)
    const payloadOff = 14 + 20 + 20
    const authOff = payloadOff + 20 + avp.length
    expect(out[authOff + 8]).not.toBe(0xde)
    // padding canary cleared
    if (pad) expect(out[payloadOff + 20 + avpLen]).not.toBe(0xca)
  })
})
