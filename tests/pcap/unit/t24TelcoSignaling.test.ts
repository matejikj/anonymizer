/**
 * T24 — H.248 / RTSP / IAX2 / Skinny / H.323 telco signaling sanitizers.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpTcp, buildEthIpUdp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { identifyUnsupportedApplicationPayload } from '../../../src/pcap/sanitize/unsupportedIdentification'

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

describe('T24 registry', () => {
  it('registers telco handlers and bumps engine version', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(expect.arrayContaining(['h248', 'rtsp', 'iax2', 'skinny', 'h323']))
    expect(familyForProtocol('h248').familyId).toBe('sip')
    expect(familyForProtocol('rtsp').familyId).toBe('sip')
    expect(PCAP_ENGINE_VERSION).toBe('2.35.0')
  })

  it('no longer identify-only for H.248 / Skinny / IAX2', () => {
    expect(
      identifyUnsupportedApplicationPayload({
        data: ascii('!/MEGACO/1 [10.0.0.1]:2944\r\n'),
        offset: 0,
        length: 28,
        srcPort: 2944,
        dstPort: 2945,
        transport: 'udp',
      }),
    ).toBeNull()
  })
})

describe('T24 H.248', () => {
  it('maps MID address, masks digit string, covers nested SDP', () => {
    const phoneDigits = '420777111222'
    const payload = ascii(
      `MEGACO/1 [10.55.66.77]:2944\r\nTransaction = 1000 {\r\nContext = $ {\r\nAdd = RTP/1 {\r\nEvents = 2222 {dd/ce{ds="${phoneDigits}"}}\r\nLocal {\r\nv=0\r\no=- 1 1 IN IP4 10.55.66.77\r\ns=-\r\nc=IN IP4 10.55.66.77\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n}\r\n}\r\n}\r\n}\r\n`,
    )
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 2944, 2945, payload)
    const mapping = new SessionMapping(undefined, { seed: 't24-h248' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'h248')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'h248-digit' || c.protocol === 'sdp')).toBe(true)
    const text = new TextDecoder('latin1').decode(applyPatches(frame, result))
    expect(text.includes(phoneDigits)).toBe(false)
    expect(text.includes('10.55.66.77')).toBe(false)
    expect(text.includes('MEGACO/1')).toBe(true)
  })
})

describe('T24 RTSP', () => {
  it('maps SETUP URI host and masks Authorization', () => {
    const payload = ascii(
      'SETUP rtsp://media.corp.example/stream RTSP/1.0\r\n'
      + 'CSeq: 2\r\n'
      + 'Transport: RTP/AVP;unicast;client_port=4000-4001\r\n'
      + 'Authorization: Digest username="alice", response="SECRETRESP99"\r\n'
      + '\r\n',
    )
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 50000, 554, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't24-rtsp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'rtsp')).toBe(true)
    const text = new TextDecoder('latin1').decode(applyPatches(frame, result))
    expect(text.includes('SECRETRESP99')).toBe(false)
    expect(text.includes('media.corp.example')).toBe(false)
    expect(text.includes('SETUP')).toBe(true)
  })
})

describe('T24 IAX2', () => {
  it('maps calling number IE and masks password IE', () => {
    const phone = '420600700800'
    const pass = 'IAXSECRET99'
    const ies = new Uint8Array(2 + phone.length + 2 + pass.length)
    let o = 0
    ies[o++] = 2 // CALLING_NUMBER
    ies[o++] = phone.length
    for (let i = 0; i < phone.length; i++) ies[o++] = phone.charCodeAt(i)
    ies[o++] = 7 // PASSWORD
    ies[o++] = pass.length
    for (let i = 0; i < pass.length; i++) ies[o++] = pass.charCodeAt(i)
    const full = new Uint8Array(12 + ies.length)
    full[0] = 0x80 // F bit
    full.set(ies, 12)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 4569, 4569, full)
    const mapping = new SessionMapping(undefined, { seed: 't24-iax' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'iax2')).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes(phone)).toBe(false)
    expect(new TextDecoder('latin1').decode(out).includes(pass)).toBe(false)
  })
})

describe('T24 Skinny', () => {
  it('maps SEP MAC in Register and masks keypad', () => {
    const body = new Uint8Array(40)
    const name = 'SEP001122334455'
    for (let i = 0; i < name.length; i++) body[i] = name.charCodeAt(i)
    body[36] = 10
    body[37] = 55
    body[38] = 66
    body[39] = 77
    const msgLen = 4 + body.length // messageId + body
    const pkt = new Uint8Array(8 + msgLen)
    pkt[0] = msgLen & 0xff
    pkt[1] = (msgLen >> 8) & 0xff
    pkt[8] = 0x01 // Register
    pkt.set(body, 12)
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 50001, 2000, 1, pkt)
    const mapping = new SessionMapping(undefined, { seed: 't24-skinny' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'skinny')).toBe(true)
    const out = applyPatches(frame, result)
    const tcpPayloadOff = 14 + 20 + 20
    expect(new TextDecoder('latin1').decode(out).includes('001122334455')).toBe(false)
    expect(out[tcpPayloadOff + 12]).toBe('S'.charCodeAt(0))
    expect(out[tcpPayloadOff + 13]).toBe('E'.charCodeAt(0))
    expect(out[tcpPayloadOff + 14]).toBe('P'.charCodeAt(0))
  })
})

describe('T24 H.323', () => {
  it('maps Q.931 called party number and masks H.225 UUIE tail', () => {
    const digits = '420111222333'
    // TPKT + Q.931 SETUP with Called Party Number + User-User (H.225 stand-in)
    const numIeLen = 1 + digits.length
    const uuieLen = 8
    const q931 = new Uint8Array(4 + 2 + numIeLen + 2 + uuieLen)
    q931[0] = 0x08 // PD
    q931[1] = 0x01 // call ref len
    q931[2] = 0x01 // call ref
    q931[3] = 0x05 // SETUP
    q931[4] = 0x70 // Called party number
    q931[5] = numIeLen
    q931[6] = 0x81 // type/plan
    for (let i = 0; i < digits.length; i++) q931[7 + i] = digits.charCodeAt(i)
    const uuieOff = 7 + digits.length
    q931[uuieOff] = 0x7e // User-user IE
    q931[uuieOff + 1] = uuieLen
    for (let i = 0; i < uuieLen; i++) q931[uuieOff + 2 + i] = 0xaa
    const tpktLen = 4 + q931.length
    const payload = new Uint8Array(tpktLen)
    payload[0] = 3
    payload[1] = 0
    payload[2] = (tpktLen >> 8) & 0xff
    payload[3] = tpktLen & 0xff
    payload.set(q931, 4)
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 50002, 1720, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't24-h323' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'h323')).toBe(true)
    // Parent must not silently claim covered when UUIE/H.225 was mask-only.
    expect(result.coverage.some((c) => c.protocol === 'h323' && c.status === 'redacted')).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes(digits)).toBe(false)
    // User-user / H.225 body masked
    expect(out[14 + 20 + 20 + 4 + uuieOff + 2]).not.toBe(0xaa)
  })
})
