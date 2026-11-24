/**
 * T39 — RDP / VNC / X11 / IPMI remote-access auth and identity canaries.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp, buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { SEMANTIC_SERVICE_PORTS } from '../../../src/pcap/anonymization/portPolicy'

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

describe('T39 registry', () => {
  it('registers remote-access handlers, family, ports, and engine 2.12.0', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(expect.arrayContaining(['rdp', 'vnc', 'x11', 'ipmi', 'citrix', 'amt']))
    expect(familyForProtocol('rdp').familyId).toBe('management')
    expect(familyForProtocol('vnc-auth').familyId).toBe('management')
    expect(familyForProtocol('ipmi').familyId).toBe('management')
    expect(SEMANTIC_SERVICE_PORTS.has(3389)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(623)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})

describe('T39 RDP cookie', () => {
  it('maps mstshash username and never leaves canary user in output', () => {
    const cookie = 'Cookie: mstshash=canary.user\r\n'
    const cookieBytes = new TextEncoder().encode(cookie)
    // TPKT + X.224 CR minimal + cookie
    const payload = new Uint8Array(11 + cookieBytes.length)
    payload[0] = 3
    payload[1] = 0
    const total = payload.length
    payload[2] = (total >> 8) & 0xff
    payload[3] = total & 0xff
    payload[4] = 6 + cookieBytes.length // LI
    payload[5] = 0xe0 // CR
    payload[6] = 0
    payload[7] = 0
    payload[8] = 0
    payload[9] = 0
    payload[10] = 0
    payload.set(cookieBytes, 11)
    const frame = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 3389, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't39-rdp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'rdp-cookie' || c.protocol === 'rdp')).toBe(true)
    const out = applyPatches(frame, result)
    expect(latin1(out).includes('canary.user')).toBe(false)
    expect(latin1(out).includes('Cookie: mstshash=')).toBe(true)
  })
})

describe('T39 VNC auth', () => {
  it('masks 16-byte DES challenge and does not leak canary', () => {
    const version = new TextEncoder().encode('RFB 003.008\n')
    const security = new Uint8Array([1, 2]) // 1 type: VNC auth
    const challenge = new TextEncoder().encode('VNCAUTH-CANARY!!') // 16
    const payload = new Uint8Array(version.length + security.length + challenge.length)
    payload.set(version, 0)
    payload.set(security, version.length)
    payload.set(challenge, version.length + security.length)
    const frame = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5900, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't39-vnc' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'vnc-auth')).toBe(true)
    const out = applyPatches(frame, result)
    expect(latin1(out).includes('VNCAUTH-CANARY!!')).toBe(false)
  })
})

describe('T39 X11 auth', () => {
  it('masks MIT-MAGIC-COOKIE-1 auth data', () => {
    const name = new TextEncoder().encode('MIT-MAGIC-COOKIE-1')
    const data = new TextEncoder().encode('COOKIE-CANARY-16B') // 16
    const namePad = (4 - (name.length % 4)) % 4
    const dataPad = (4 - (data.length % 4)) % 4
    const payload = new Uint8Array(12 + name.length + namePad + data.length + dataPad)
    payload[0] = 0x42 // MSB first
    payload[2] = 0
    payload[3] = 11 // major
    payload[4] = 0
    payload[5] = 0 // minor
    payload[6] = (name.length >> 8) & 0xff
    payload[7] = name.length & 0xff
    payload[8] = (data.length >> 8) & 0xff
    payload[9] = data.length & 0xff
    payload.set(name, 12)
    payload.set(data, 12 + name.length + namePad)
    const frame = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 6000, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't39-x11' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'x11-auth')).toBe(true)
    const out = applyPatches(frame, result)
    expect(latin1(out).includes('COOKIE-CANARY-16B')).toBe(false)
  })
})

describe('T39 IPMI RAKP', () => {
  it('maps RAKP1 username and masks console random', () => {
    const user = new TextEncoder().encode('bmc-canary')
    // RMCP(4) + RMCP+(12) + RAKP1 body
    const body = new Uint8Array(28 + user.length)
    body[0] = 1 // tag
    // managed SID at 4
    body[4] = 0x11
    body[5] = 0x22
    body[6] = 0x33
    body[7] = 0x44
    // console random 16 bytes canary
    const rnd = new TextEncoder().encode('IPMI-RND-CANARY!!')
    body.set(rnd, 8)
    body[24] = 4 // priv
    body[27] = user.length
    body.set(user, 28)

    const payload = new Uint8Array(16 + body.length)
    payload[0] = 0x06 // RMCP ver
    payload[3] = 0x07 // IPMI class
    payload[4] = 0x06 // RMCP+ auth
    payload[5] = 0x12 // RAKP1
    payload.set(body, 16)

    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 623, 623, payload)
    const mapping = new SessionMapping(undefined, { seed: 't39-ipmi' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'ipmi-rakp-auth' || c.protocol === 'ipmi-rakp-user')).toBe(
      true,
    )
    const out = applyPatches(frame, result)
    expect(latin1(out).includes('IPMI-RND-CANARY!!')).toBe(false)
    expect(latin1(out).includes('bmc-canary')).toBe(false)
  })
})
