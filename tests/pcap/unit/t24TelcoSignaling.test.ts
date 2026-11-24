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
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
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
    const uuieLen = 8
    const { payload, uuieDataOff } = buildH323Setup({ calledDigits: digits, uuieLen })
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 50002, 1720, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't24-h323' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'h323')).toBe(true)
    // Parent must not silently claim covered when UUIE/H.225 was mask-only.
    expect(result.coverage.some((c) => c.protocol === 'h323' && c.status === 'redacted')).toBe(true)
    // H.225.0 two-octet User-user length must not be read as a truncated IE.
    expect(result.coverage.some((c) => c.protocol.startsWith('h323') && c.status === 'malformed')).toBe(false)
    expect(result.coverage.some((c) => c.protocol === 'h323-uuie' && c.status === 'redacted')).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes(digits)).toBe(false)
    // User-user / H.225 body masked
    for (let i = 0; i < uuieLen; i++) expect(out[14 + 20 + 20 + uuieDataOff + i]).not.toBe(0xaa)
  })

  it('parses IEs around a User-user IE longer than 255 bytes (two-octet length)', () => {
    const display = 'Dispatcher Test'
    const { payload, uuieDataOff } = buildH323Setup({ display, calledDigits: '555123', uuieLen: 300 })
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 50002, 1720, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't24-h323-long' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('h323') && c.status === 'malformed')).toBe(false)
    expect(result.coverage.find((c) => c.protocol === 'h323-uuie')?.length).toBe(300)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes(display)).toBe(false)
    expect(text.includes('555123')).toBe(false)
    expect(out[14 + 20 + 20 + uuieDataOff + 299]).not.toBe(0xaa)
  })
})

/** TPKT + Q.931 SETUP as used by H.225.0: optional Display, Called Party Number, User-user. */
function buildH323Setup(input: { display?: string; calledDigits: string; uuieLen: number }): {
  payload: Uint8Array
  uuieDataOff: number
} {
  const ies: number[] = []
  if (input.display) {
    ies.push(0x28, input.display.length, ...[...input.display].map((ch) => ch.charCodeAt(0)))
  }
  ies.push(0x70, 1 + input.calledDigits.length, 0x81, ...[...input.calledDigits].map((ch) => ch.charCodeAt(0)))
  // User-user IE: H.225.0 codes its length in two octets.
  ies.push(0x7e, (input.uuieLen >> 8) & 0xff, input.uuieLen & 0xff)
  const q931Header = [0x08, 0x01, 0x01, 0x05] // PD, call ref len, call ref, SETUP
  const uuieDataOff = 4 + q931Header.length + ies.length
  const tpktLen = uuieDataOff + input.uuieLen
  const payload = new Uint8Array(tpktLen)
  payload.set([3, 0, (tpktLen >> 8) & 0xff, tpktLen & 0xff], 0)
  payload.set(q931Header, 4)
  payload.set(ies, 4 + q931Header.length)
  payload.fill(0xaa, uuieDataOff)
  return { payload, uuieDataOff }
}
