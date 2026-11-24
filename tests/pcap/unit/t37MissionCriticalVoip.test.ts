/**
 * T37 — MCPTT XML, DTMF-relay, MSRP, BFCP, ZRTP, T.38 baseline.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp, buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { planSipBodyOperations } from '../../../src/pcap/protocols/application/sip/bodyOperations'
import { parseSipMessages } from '../../../src/pcap/protocols/application/sip/parser'
import { sanitizeT38Udptl } from '../../../src/pcap/sanitize/t38'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { MediaFlowIndex } from '../../../src/pcap/discovery/mediaFlowIndex'

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

describe('T37 registry', () => {
  it('registers MC VoIP handlers', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(expect.arrayContaining(['msrp', 'bfcp', 't38', 'zrtp']))
    expect(familyForProtocol('msrp').familyId).toBe('sip')
    expect(familyForProtocol('zrtp').familyId).toBe('rtp-rtcp')
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
  })
})

function buildSipBytes(headers: string[], body: string): Uint8Array {
  const all = [...headers, `Content-Length: ${body.length}`]
  const text = `${all.join('\r\n')}\r\n\r\n${body}`
  return new TextEncoder().encode(text)
}

describe('T37 MCPTT / DTMF SIP bodies', () => {
  it('maps mcptt-calling-user-id and masks location', () => {
    const xml =
      '<?xml version="1.0"?>\r\n'
      + '<mcptt-info>\r\n'
      + '<mcptt-calling-user-id>sip:canary-mc@example.com</mcptt-calling-user-id>\r\n'
      + '<mcptt-location-info>LOC-CANARY-55.1,12.2</mcptt-location-info>\r\n'
      + '<mcptt-request-type>private</mcptt-request-type>\r\n'
      + '</mcptt-info>'
    const bytes = buildSipBytes(
      [
        'MESSAGE sip:group@example.com SIP/2.0',
        'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-mc',
        'From: <sip:canary-mc@example.com>;tag=mc1',
        'To: <sip:group@example.com>',
        'Call-ID: mcptt-call-001',
        'CSeq: 1 MESSAGE',
        'Max-Forwards: 70',
        'Content-Type: application/vnd.3gpp.mcptt-info+xml',
      ],
      xml,
    )
    const stream = parseSipMessages(bytes)
    expect(stream.messages.length).toBe(1)
    const message = stream.messages[0]!.message
    const plan = planSipBodyOperations(message, bytes)
    expect(plan.coverage.some((c) => c.protocol === 'sip-mcptt')).toBe(true)
    expect(plan.operations.some((o) => o.action === 'map' && o.canonicalText.includes('canary-mc'))).toBe(
      true,
    )
    expect(plan.operations.some((o) => o.action === 'redact' && o.canonicalText.includes('LOC-CANARY'))).toBe(
      true,
    )

    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, bytes)
    const mapping = new SessionMapping(undefined, { seed: 't37-mc' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('LOC-CANARY')).toBe(false)
    expect(text.includes('canary-mc@example.com')).toBe(false)
  })

  it('masks DTMF-relay Signal token', () => {
    const body = 'Signal=5\r\nDuration=100\r\n'
    const bytes = buildSipBytes(
      [
        'INFO sip:b@example.com SIP/2.0',
        'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-dtmf',
        'From: <sip:a@example.com>;tag=d1',
        'To: <sip:b@example.com>;tag=d2',
        'Call-ID: dtmf-001',
        'CSeq: 2 INFO',
        'Max-Forwards: 70',
        'Content-Type: application/dtmf-relay',
      ],
      body,
    )
    const message = parseSipMessages(bytes).messages[0]!.message
    const plan = planSipBodyOperations(message, bytes)
    expect(plan.operations.some((o) => o.action === 'redact' && o.canonicalText === '5')).toBe(true)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, bytes)
    const mapping = new SessionMapping(undefined, { seed: 't37-dtmf' })
    const out = applyPatches(frame, sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping))
    expect(new TextDecoder('latin1').decode(out).includes('Signal=5')).toBe(false)
    expect(new TextDecoder('latin1').decode(out).includes('Duration=100')).toBe(true)
  })
})

describe('T37 MSRP / BFCP / ZRTP / T.38', () => {
  it('sanitizes MSRP path and masks body canary', () => {
    const txn = 'abc123'
    const msg =
      `MSRP ${txn} SEND\r\n`
      + 'To-Path: msrp://10.9.8.7:2855/sesscanary;tcp\r\n'
      + 'From-Path: msrp://10.9.8.8:2855/sessother;tcp\r\n'
      + `Message-ID: mid-canary\r\n`
      + 'Byte-Range: 1-11/11\r\n'
      + 'Content-Type: text/plain\r\n'
      + '\r\n'
      + 'SECRET-BODY\r\n'
      + `-------${txn}$\r\n`
    const payload = new TextEncoder().encode(msg)
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 28_55, 28_55, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't37-msrp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'msrp')).toBe(true)
    const text = new TextDecoder('latin1').decode(applyPatches(frame, result))
    expect(text.includes('SECRET-BODY')).toBe(false)
    expect(text.includes('10.9.8.7')).toBe(false)
  })

  it('maps BFCP conference/user IDs', () => {
    const pkt = new Uint8Array(16)
    pkt[0] = 0x20 // ver=1
    pkt[1] = 0x01 // FloorRequest
    pkt[2] = 0x01 // 1 word payload
    pkt[3] = 0
    pkt[4] = 0xca
    pkt[5] = 0xfe
    pkt[6] = 0xba
    pkt[7] = 0xbe // conf
    pkt[8] = 0xde
    pkt[9] = 0xad
    pkt[10] = 0xbe
    pkt[11] = 0xef // user
    pkt[12] = 0x01
    pkt[13] = 0
    pkt[14] = 0x01
    pkt[15] = 0 // attr
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 5000, pkt)
    const mapping = new SessionMapping(undefined, { seed: 't37-bfcp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'bfcp')).toBe(true)
    const out = applyPatches(frame, result)
    expect([...out.subarray(14 + 20 + 8 + 4, 14 + 20 + 8 + 8)]).not.toEqual([0xca, 0xfe, 0xba, 0xbe])
  })

  it('maps ZRTP ZID and strips Hello hash canary', () => {
    const pkt = new Uint8Array(84)
    pkt[0] = 0x10
    pkt[1] = 0x00
    pkt[2] = 0
    pkt[3] = 80
    pkt.set(new TextEncoder().encode('ZRTP'), 4)
    pkt.set(new TextEncoder().encode('Hello   '), 8)
    pkt.set(new TextEncoder().encode('1.10'), 16)
    pkt.set(new TextEncoder().encode('ClientID-CANARY!!'), 20)
    for (let i = 0; i < 32; i++) pkt[36 + i] = 0xa0 + (i & 0x0f) // H3
    for (let i = 0; i < 12; i++) pkt[68 + i] = 0x10 + i // ZID
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 4000, 4000, pkt)
    const mapping = new SessionMapping(undefined, { seed: 't37-zrtp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'zrtp')).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('ClientID-CANARY')).toBe(false)
    expect([...out.subarray(14 + 20 + 8 + 68, 14 + 20 + 8 + 80)]).not.toEqual(
      Array.from({ length: 12 }, (_, i) => 0x10 + i),
    )
  })

  it('masks T.38 IFP after sequence', () => {
    const udptl = new Uint8Array([0x00, 0x07, 0x01, 0x02, 0x54, 0x53, 0x49, 0x43, 0x41, 0x4e])
    const collector = new PatchCollector(udptl.length)
    const mapping = new SessionMapping(undefined, { seed: 't37-t38' })
    const r = sanitizeT38Udptl(udptl, 0, udptl.length, collector, mapping, undefined, 0)
    expect(r).not.toBeNull()
    collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
    const out = udptl.slice()
    for (const p of collector.getPatches()) out.set(p.data, p.offset)
    expect(out[0]).toBe(0x00)
    expect(out[1]).toBe(0x07)
    expect(new TextDecoder('latin1').decode(out).includes('TSICAN')).toBe(false)
  })

  it('engine wires T.38 when SDP registers UDPTL/t38 (does not steal bare UDP)', () => {
    const mediaPort = 6004
    const mediaIndex = new MediaFlowIndex()
    const mapping = new SessionMapping(undefined, { seed: 't37-t38-engine' })
    const sdp = [
      'v=0',
      'o=- 1 1 IN IP4 192.168.1.10',
      's=-',
      'c=IN IP4 192.168.1.10',
      't=0 0',
      `m=image ${mediaPort} UDPTL t38`,
      'a=T38FaxVersion:0',
      '',
    ].join('\r\n')
    const sipText = [
      'INVITE sip:b@10.0.0.2 SIP/2.0',
      'Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK-t38',
      'From: <sip:a@192.168.1.10>;tag=t38',
      'To: <sip:b@10.0.0.2>',
      'Call-ID: t38-engine@host',
      'CSeq: 1 INVITE',
      'Content-Type: application/sdp',
      `Content-Length: ${sdp.length}`,
      '',
      sdp,
    ].join('\r\n')
    const sipPkt = buildEthIpUdp(
      [192, 168, 1, 10],
      [10, 0, 0, 2],
      5060,
      5060,
      new TextEncoder().encode(sipText),
    )
    sanitizePacket(packetInput(sipPkt), DIAGNOSTIC_POLICY, mapping, { mediaFlowIndex: mediaIndex })
    expect(mediaIndex.isLikelyT38Endpoint('192.168.1.10', mediaPort)).toBe(true)

    const udptl = new Uint8Array([0x00, 0x07, 0x01, 0x02, 0x54, 0x53, 0x49, 0x43, 0x41, 0x4e])
    const frame = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort, 40_000, udptl)
    const r = sanitizePacket(
      { ...packetInput(frame), index: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { mediaFlowIndex: mediaIndex },
    )
    expect(r.coverage.some((c) => c.protocol === 't38' || c.protocol === 't38-ifp')).toBe(true)
    const out = applyPatches(frame, r)
    expect(out[14 + 20 + 8]).toBe(0x00)
    expect(out[14 + 20 + 8 + 1]).toBe(0x07)
    expect(new TextDecoder('latin1').decode(out).includes('TSICAN')).toBe(false)

    // Without SDP registration, weak UDPTL sniff must not claim random UDP.
    const bare = sanitizePacket(
      packetInput(frame),
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 't37-t38-bare' }),
    )
    expect(bare.coverage.some((c) => c.protocol === 't38' || c.protocol === 't38-ifp')).toBe(false)
  })
})
