/**
 * T18 — LLMNR, NBNS, SSDP, WS-Discovery structured sanitizers.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { UNSUPPORTED_PROTOCOL_NAMES } from '../../../src/pcap/sanitize/unsupportedIdentification'
import {
  decodeNetbiosFirstLevel,
  encodeNetbiosFirstLevel,
  joinNetbiosName,
  splitNetbiosName,
} from '../../../src/pcap/sanitize/netbiosNameCodec'
import { GENERIC_NOTIFY_CORPUS } from '../../../src/pcap/protocols/application/textproto'

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

function ascii(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

describe('T18 registry', () => {
  it('registers discovery handlers and families', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(expect.arrayContaining(['llmnr', 'nbns', 'ssdp', 'ws-discovery']))
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('ssdp')
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('llmnr')
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('netbios')
    expect(familyForProtocol('ssdp').familyId).toBe('discovery')
    expect(familyForProtocol('llmnr').familyId).toBe('discovery')
    expect(familyForProtocol('nbns').familyId).toBe('discovery')
    expect(familyForProtocol('ws-discovery').familyId).toBe('discovery')
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
  })
})

describe('T18 NetBIOS codec', () => {
  it('round-trips first-level encode/decode with suffix preserved', () => {
    const joined = joinNetbiosName('HOSTCANARY', 0x00)!
    const enc = encodeNetbiosFirstLevel(joined)!
    expect(enc.length).toBe(32)
    const dec = decodeNetbiosFirstLevel(enc)!
    const split = splitNetbiosName(dec)!
    expect(split.host).toBe('hostcanary')
    expect(split.suffix).toBe(0x00)
  })
})

describe('T18 hostname alias parity', () => {
  it('DNS, LLMNR, NBNS and text mapping share the same hostname alias', () => {
    const seed = 't18-host-parity'
    const host = 'pcname'
    const constraint = { kind: 'text-ascii' as const, byteLength: host.length }
    const mDns = new SessionMapping(undefined, { seed })
    const mLlmnr = new SessionMapping(undefined, { seed })
    const mNbns = new SessionMapping(undefined, { seed })
    const mText = new SessionMapping(undefined, { seed })
    const aDns = mDns.aliasFor('hostname', host, constraint, host)
    const aLlmnr = mLlmnr.aliasFor('hostname', host, constraint, host)
    const aNbns = mNbns.aliasFor('hostname', host, constraint, host)
    const aText = mText.aliasFor('hostname', host, constraint, host)
    expect(aDns).toBe(aLlmnr)
    expect(aDns).toBe(aNbns)
    expect(aDns).toBe(aText)
    expect(aDns).not.toBe(host)
  })
})

describe('T18 SSDP', () => {
  it('maps HOST IP and USN uuid; covers ssdp not unsupported', () => {
    const payload = ascii(GENERIC_NOTIFY_CORPUS)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1900, 1900, payload)
    const mapping = new SessionMapping(undefined, { seed: 't18-ssdp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'ssdp')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'unsupported:ssdp')).toBe(false)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('10.0.0.50')).toBe(false)
    expect(text.includes('uuid:demo-0001')).toBe(false)
  })
})

describe('T18 LLMNR', () => {
  it('covers LLMNR DNS-shaped query on 5355', () => {
    // Minimal DNS query: header + label "a" + root + type A + class IN
    const q = new Uint8Array([
      0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x01, 0x61, 0x00,
      0x00, 0x01, 0x00, 0x01,
    ])
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5355, 5355, q)
    const mapping = new SessionMapping(undefined, { seed: 't18-llmnr' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'llmnr')).toBe(true)
  })
})

describe('T18 NBNS', () => {
  it('maps encoded NetBIOS question name', () => {
    const raw = joinNetbiosName('PCNAME', 0x00)!
    const enc = encodeNetbiosFirstLevel(raw)!
    const q = new Uint8Array(12 + 1 + 32 + 1 + 4)
    q[4] = 0
    q[5] = 1 // qdcount
    q[12] = 32
    q.set(enc, 13)
    q[45] = 0 // root
    q[46] = 0x00
    q[47] = 0x20 // NB
    q[48] = 0x00
    q[49] = 0x01 // IN
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 137, 137, q)
    const mapping = new SessionMapping(undefined, { seed: 't18-nbns' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'nbns')).toBe(true)
    const out = applyPatches(frame, result)
    const payloadOff = 14 + 20 + 8
    const encOut = out.subarray(payloadOff + 13, payloadOff + 45)
    const dec = decodeNetbiosFirstLevel(encOut)
    expect(dec).not.toBeNull()
    const split = splitNetbiosName(dec!)!
    expect(split.host).not.toBe('pcname')
    expect(split.suffix).toBe(0x00)
  })
})

describe('T18 WS-Discovery', () => {
  it('maps urn:uuid in SOAP envelope', () => {
    const soap = [
      '<?xml version="1.0"?>',
      '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"',
      ' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">',
      '<s:Header><wsa:MessageID>urn:uuid:12345678-1234-1234-1234-1234567890ab</wsa:MessageID></s:Header>',
      '<s:Body><Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery"/></s:Body>',
      '</s:Envelope>',
    ].join('')
    const payload = ascii(soap)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 3702, 3702, payload)
    const mapping = new SessionMapping(undefined, { seed: 't18-wsd' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'ws-discovery')).toBe(true)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('12345678-1234-1234-1234-1234567890ab')).toBe(false)
  })
})
