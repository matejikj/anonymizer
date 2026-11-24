/**
 * T52 — SMPP bind/submit/deliver canaries (password, addresses, short_message).
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { SEMANTIC_SERVICE_PORTS } from '../../../src/pcap/anonymization/portPolicy'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'

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

function writeU32(buf: Uint8Array, o: number, v: number): void {
  buf[o] = (v >>> 24) & 0xff
  buf[o + 1] = (v >>> 16) & 0xff
  buf[o + 2] = (v >>> 8) & 0xff
  buf[o + 3] = v & 0xff
}

function cOctet(s: string): Uint8Array {
  const out = new Uint8Array(s.length + 1)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  out[s.length] = 0
  return out
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

function wrapPdu(commandId: number, status: number, seq: number, body: Uint8Array): Uint8Array {
  const len = 16 + body.length
  const out = new Uint8Array(len)
  writeU32(out, 0, len)
  writeU32(out, 4, commandId)
  writeU32(out, 8, status)
  writeU32(out, 12, seq)
  out.set(body, 16)
  return out
}

describe('T52 registry', () => {
  it('registers smpp handler, family, port, and engine 2.35.0', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('smpp')
    expect(familyForProtocol('smpp').familyId).toBe('smpp')
    expect(familyForProtocol('smpp-sm').familyId).toBe('smpp')
    expect(SEMANTIC_SERVICE_PORTS.has(2775)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.35.0')
  })
})

describe('T52 bind_transmitter', () => {
  it('masks password and maps system_id', () => {
    const body = concat(
      cOctet('smppuser'),
      cOctet('SECRET-SMPP-PASS'),
      cOctet('VMA'),
      Uint8Array.of(0x34, 0x00, 0x00), // interface_version, ton, npi
      cOctet(''),
    )
    const pdu = wrapPdu(0x00000002, 0, 1, body)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 2775, 1, pdu)
    const mapping = new SessionMapping(undefined, { seed: 't52-bind' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('smpp'))).toBe(true)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('SECRET-SMPP-PASS')).toBe(false)
    expect(out.includes('smppuser')).toBe(false)
  })
})

describe('T52 submit_sm', () => {
  it('maps addresses and masks short_message including DLR-like text', () => {
    const sm = 'id:MSG-CANARY-99 text:Hello secret SMS body'
    const smBytes = new TextEncoder().encode(sm)
    const body = concat(
      cOctet(''), // service_type
      Uint8Array.of(0x01, 0x01), // source ton/npi
      cOctet('AlphaSender'),
      Uint8Array.of(0x01, 0x01), // dest ton/npi
      cOctet('420111222333'),
      Uint8Array.of(0x00, 0x00, 0x00), // esm, protocol, priority
      cOctet(''), // schedule
      cOctet(''), // validity
      Uint8Array.of(0x01, 0x00, 0x00, 0x00), // registered, replace, dcs, default_msg
      Uint8Array.of(smBytes.length),
      smBytes,
    )
    const pdu = wrapPdu(0x00000004, 0, 7, body)
    const pkt = buildEthIpTcp([192, 0, 2, 10], [192, 0, 2, 20], 50_000, 2775, 1, pdu)
    const mapping = new SessionMapping(undefined, { seed: 't52-submit' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('420111222333')).toBe(false)
    expect(out.includes('AlphaSender')).toBe(false)
    expect(out.includes('Hello secret SMS body')).toBe(false)
    expect(out.includes('MSG-CANARY-99')).toBe(false)
    expect(result.issues.some((i) => i.includes('short-message'))).toBe(true)
  })

  it('maps submit_sm_resp message_id', () => {
    const body = cOctet('smsc-msg-id-CANARY')
    const pdu = wrapPdu(0x80000004, 0, 7, body)
    const pkt = buildEthIpTcp([192, 0, 2, 20], [192, 0, 2, 10], 2775, 50_000, 1, pdu)
    const mapping = new SessionMapping(undefined, { seed: 't52-resp' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('smsc-msg-id-CANARY')).toBe(false)
    expect(result.coverage.some((c) => c.protocol === 'smpp-id')).toBe(true)
  })
})

describe('T52 message_payload TLV', () => {
  it('masks message_payload optional TLV', () => {
    const payload = new TextEncoder().encode('TLV-PAYLOAD-SECRET-CANARY')
    const tlv = new Uint8Array(4 + payload.length)
    tlv[0] = 0x04
    tlv[1] = 0x24
    tlv[2] = (payload.length >> 8) & 0xff
    tlv[3] = payload.length & 0xff
    tlv.set(payload, 4)
    // Minimal data_sm mandatory: service_type, src ton/npi/addr, dst ton/npi/addr, esm, reg, dcs
    const body = concat(
      cOctet(''),
      Uint8Array.of(0x01, 0x01),
      cOctet('420999888777'),
      Uint8Array.of(0x01, 0x01),
      cOctet('420111222333'),
      Uint8Array.of(0x00, 0x00, 0x00),
      tlv,
    )
    const pdu = wrapPdu(0x00000103, 0, 3, body)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 2775, 1, pdu)
    const mapping = new SessionMapping(undefined, { seed: 't52-tlv' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('TLV-PAYLOAD-SECRET-CANARY')).toBe(false)
    expect(out.includes('420999888777')).toBe(false)
  })
})
