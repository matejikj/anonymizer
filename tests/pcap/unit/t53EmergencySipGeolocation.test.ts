/**
 * T53 — emergency SIP Geolocation / PIDF-LO / LoST canaries.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { planSipBodyOperations } from '../../../src/pcap/protocols/application/sip/bodyOperations'
import { parseSipMessages } from '../../../src/pcap/protocols/application/sip/parser'
import { extractSipEntities } from '../../../src/pcap/protocols/application/sip/extract'

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

const PIDF_BODY = [
  '<?xml version="1.0"?>',
  '<presence entity="pres:alice@example.com">',
  '<tuple id="tuple-canary-1">',
  '<status><geopriv>',
  '<location-info><gmlCode>',
  '<country>CZ</country>',
  '<A1>Prague</A1>',
  '<HNO>42</HNO>',
  '<FLR>3</FLR>',
  '</gmlCode>',
  '<gmlLoc><pos>50.087 14.421</pos></gmlLoc>',
  '</location-info>',
  '</geopriv></status>',
  '</tuple></presence>',
].join('')

describe('T53 registry', () => {
  it('registers pidf/lost handlers, family, and engine 2.36.1', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('pidf')
    expect(ids).toContain('lost')
    expect(familyForProtocol('sip-pidf').familyId).toBe('emergency-location')
    expect(familyForProtocol('sip-lost').familyId).toBe('emergency-location')
    expect(familyForProtocol('pidf').familyId).toBe('emergency-location')
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})

describe('T53 Geolocation header', () => {
  it('maps cid token and masks location URI; preserves Resource-Priority', () => {
    const body = 'v=0\r\no=- 0 0 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n'
    const msg = [
      'INVITE sip:sos@example.com SIP/2.0',
      'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-1',
      'From: <sip:caller@example.com>;tag=1',
      'To: <sip:sos@example.com>',
      'Call-ID: emerg-call-1',
      'CSeq: 1 INVITE',
      'Resource-Priority: esnet.0',
      'Geolocation: <cid:loc-part@example.com>',
      'Geolocation: <https://lis.example.com/loc/TOKEN-SECRET-CANARY>',
      'Geolocation-Routing: yes',
      'Content-Type: application/sdp',
      `Content-Length: ${body.length}`,
      '',
      body,
    ].join('\r\n')
    const buf = new TextEncoder().encode(msg)
    const stream = parseSipMessages(buf)
    expect(stream.messages.length).toBe(1)
    const extracted = extractSipEntities(stream.messages[0]!.message, buf)
    const cid = extracted.entities.find((e) => e.parameterName === 'cid')
    expect(cid?.action).toBe('map')
    expect(cid?.canonicalText).toContain('loc-part@example.com')
    expect(extracted.entities.some((e) => e.action === 'redact' && e.canonicalText === '')).toBe(true)

    const pkt = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 5060, 5060, buf)
    const mapping = new SessionMapping(undefined, { seed: 't53-geo' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('TOKEN-SECRET-CANARY')).toBe(false)
    expect(out.includes('lis.example.com')).toBe(false)
    expect(out.includes('Resource-Priority: esnet.0')).toBe(true)
    expect(out.includes('Geolocation-Routing: yes')).toBe(true)
  })
})

describe('T53 PIDF-LO body', () => {
  it('redacts coordinates and civic fields; rejects XXE', () => {
    const headers = [
      'INVITE sip:sos@example.com SIP/2.0',
      'Via: SIP/2.0/UDP 192.0.2.1:5060',
      'From: <sip:a@example.com>;tag=1',
      'To: <sip:sos@example.com>',
      'Call-ID: pidf-call-1',
      'CSeq: 1 INVITE',
      'Content-Type: application/pidf+xml',
      `Content-Length: ${PIDF_BODY.length}`,
    ]
    const buf = new TextEncoder().encode(`${headers.join('\r\n')}\r\n\r\n${PIDF_BODY}`)
    const stream = parseSipMessages(buf)
    const plan = planSipBodyOperations(stream.messages[0]!.message, buf)
    expect(plan.coverage.some((c) => c.protocol === 'sip-pidf')).toBe(true)
    expect(plan.operations.some((o) => o.action === 'redact')).toBe(true)

    const pkt = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 5060, 5060, buf)
    const mapping = new SessionMapping(undefined, { seed: 't53-pidf' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('50.087')).toBe(false)
    expect(out.includes('14.421')).toBe(false)
    expect(out.includes('Prague')).toBe(false)
    expect(out.includes('pres:alice@example.com')).toBe(false)

    const xxe = '<!DOCTYPE presence [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><presence>&xxe;</presence>'
    const xxeBuf = new TextEncoder().encode(
      [
        'INVITE sip:sos@example.com SIP/2.0',
        'Via: SIP/2.0/UDP 192.0.2.1:5060',
        'From: <sip:a@example.com>;tag=1',
        'To: <sip:sos@example.com>',
        'Call-ID: xxe-1',
        'CSeq: 1 INVITE',
        'Content-Type: application/pidf+xml',
        `Content-Length: ${xxe.length}`,
        '',
        xxe,
      ].join('\r\n'),
    )
    const xxePlan = planSipBodyOperations(parseSipMessages(xxeBuf).messages[0]!.message, xxeBuf)
    expect(xxePlan.issues.some((i) => i.includes('xxe'))).toBe(true)
  })
})

describe('T53 LoST body', () => {
  it('masks serviceBoundary and displayName; preserves sos URN', () => {
    const lost = [
      '<findService xmlns="urn:oasis:names:tc:emergency:lost:2.0">',
      '<requestId>lost-req-CANARY</requestId>',
      '<service>urn:service:sos.police</service>',
      '<displayName>PSAP Secret Name</displayName>',
      '<uri>https://psap.example.com/call/TOKEN</uri>',
      '<serviceBoundary><pos>1.0 2.0</pos></serviceBoundary>',
      '</findService>',
    ].join('')
    const headers = [
      'MESSAGE sip:lost@example.com SIP/2.0',
      'Via: SIP/2.0/UDP 192.0.2.1:5060',
      'From: <sip:a@example.com>;tag=1',
      'To: <sip:lost@example.com>',
      'Call-ID: lost-call-1',
      'CSeq: 1 MESSAGE',
      'Content-Type: application/lost+xml',
      `Content-Length: ${lost.length}`,
    ]
    const buf = new TextEncoder().encode(`${headers.join('\r\n')}\r\n\r\n${lost}`)
    const plan = planSipBodyOperations(parseSipMessages(buf).messages[0]!.message, buf)
    expect(plan.coverage.some((c) => c.protocol === 'sip-lost')).toBe(true)

    const pkt = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 5060, 5060, buf)
    const mapping = new SessionMapping(undefined, { seed: 't53-lost' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('PSAP Secret Name')).toBe(false)
    expect(out.includes('psap.example.com')).toBe(false)
    expect(out.includes('1.0 2.0')).toBe(false)
    expect(out.includes('urn:service:sos.police')).toBe(true)
    expect(out.includes('lost-req-CANARY')).toBe(false)
  })
})
