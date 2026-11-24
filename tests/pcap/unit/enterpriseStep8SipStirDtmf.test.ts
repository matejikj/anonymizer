/**
 * Enterprise step 8 — SIP enterprise headers, STIR/SHAKEN Identity, DTMF telephone-event.
 */

import { describe, expect, it } from 'vitest'
import { SessionMapping, DEFAULT_MAPPING_CONFIG } from '../../../src/pcap/anonymization/mapping'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import {
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  sanitizePacket,
  PatchCollector,
  TELEPHONE_EVENT_ISSUE,
} from '../../../src/pcap/sanitize'
import { dispositionForHeader } from '../../../src/pcap/protocols/application/sip/headerPolicy'
import {
  extractSipEntities,
  parseSipMessage,
  sanitizeStructuredSipMessage,
} from '../../../src/pcap/protocols/application/sip'
import { CRYPTO_INTEGRITY_ISSUE, resolveCryptographicIntegrity } from '../../../src/pcap/trust'
import { MediaFlowIndex } from '../../../src/pcap/discovery/mediaFlowIndex'
import { collectTelephoneEventPayloadTypes } from '../../../src/pcap/protocols/application/sdp/attributes'
import { parseSdp } from '../../../src/pcap/protocols/application/sdp/parser'
import { buildSdpMediaEndpoints } from '../../../src/pcap/protocols/application/sdp/mediaModel'

function latin1(text: string): Uint8Array {
  return new Uint8Array([...text].map((c) => c.charCodeAt(0) & 0xff))
}

function buildEthIpUdp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const total = 14 + 20 + 8 + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + 8 + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = 17
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  const udp = 34
  buf[udp] = (srcPort >> 8) & 0xff
  buf[udp + 1] = srcPort & 0xff
  buf[udp + 2] = (dstPort >> 8) & 0xff
  buf[udp + 3] = dstPort & 0xff
  const udpLen = 8 + payload.length
  buf[udp + 4] = (udpLen >> 8) & 0xff
  buf[udp + 5] = udpLen & 0xff
  buf.set(payload, udp + 8)
  return buf
}

function apply(
  packet: Uint8Array,
  result: { patches: readonly { offset: number; data: Uint8Array }[] },
): Uint8Array {
  const out = packet.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

describe('enterprise step 8 — SIP enterprise headers + STIR Identity', () => {
  it('classifies new enterprise headers correctly', () => {
    expect(dispositionForHeader('p-associated-uri')).toBe('identity')
    expect(dispositionForHeader('p-called-party-id')).toBe('identity')
    expect(dispositionForHeader('service-route')).toBe('identity')
    // T53 — structured Geolocation/PIDF-LO disposition (was opaque-redact before T53).
    expect(dispositionForHeader('geolocation')).toBe('geolocation')
    expect(dispositionForHeader('identity')).toBe('stir-identity')
    expect(dispositionForHeader('identity-info')).toBe('opaque-redact')
    expect(dispositionForHeader('x-vendor-secret')).toBe('vendor-redact')
    // From/To must NOT be stir-identity
    expect(dispositionForHeader('from')).toBe('identity')
  })

  it('masks STIR Identity PASSporT and sets cryptographic_integrity MODIFIED', () => {
    const passport =
      'eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwicHB0Ijoic2hha2VuIn0.eyJvcmlnI'
      + 'iJ7InRuIjoiKzEyMTU1NTEyMTIifX0.signaturePaddingXXX'
    const buf = latin1([
      'INVITE sip:bob@example.com SIP/2.0\r\n',
      'From: <sip:alice@example.com>;tag=a1\r\n',
      'To: <sip:bob@example.com>\r\n',
      'Call-ID: dialog-stir@example.com\r\n',
      'CSeq: 1 INVITE\r\n',
      `Identity: ${passport}\r\n`,
      'P-Associated-URI: <sip:alice-alias@example.com>\r\n',
      'P-Called-Party-ID: <sip:bob@example.com>\r\n',
      'Service-Route: <sip:scscf.example.com;lr>\r\n',
      'Geolocation: <https://geo.example/loc/secret>\r\n',
      'X-Custom-Id: vendor-leak-42\r\n',
      'Content-Length: 0\r\n\r\n',
    ].join(''))

    const parsed = parseSipMessage(buf)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return

    const { entities, issues } = extractSipEntities(parsed.message, buf)
    expect(issues).toContain(CRYPTO_INTEGRITY_ISSUE.sipIdentity)
    // From must not alone trigger crypto MODIFIED via stir path — only Identity header.
    expect(issues.filter((i) => i.includes('sip-identity')).length).toBe(1)

    const identityEntities = entities.filter((e) => e.headerCanonicalName === 'identity')
    expect(identityEntities.length).toBe(1)
    expect(identityEntities[0]?.action).toBe('redact')

    expect(entities.some((e) => e.headerCanonicalName === 'p-associated-uri')).toBe(true)
    expect(entities.some((e) => e.headerCanonicalName === 'p-called-party-id')).toBe(true)
    expect(entities.some((e) => e.headerCanonicalName === 'service-route')).toBe(true)
    expect(entities.some((e) => e.headerCanonicalName === 'geolocation' && e.action === 'redact')).toBe(true)
    expect(entities.some((e) => e.headerCanonicalName === 'x-custom-id' && e.action === 'redact')).toBe(true)

    const collector = new PatchCollector(buf.length)
    const mapping = new SessionMapping(DEFAULT_MAPPING_CONFIG)
    const sipIssues = sanitizeStructuredSipMessage(buf, parsed.message, 'udp', collector, mapping)
    collector.resolveDeferred({
      mapping,
      fingerprints: new FingerprintSession(),
    })
    const out = buf.slice()
    for (const p of collector.getPatches()) out.set(p.data, p.offset)
    const text = new TextDecoder('latin1').decode(out)
    expect(text).not.toContain(passport)
    expect(text).not.toContain('vendor-leak-42')
    expect(text).not.toContain('geo.example/loc/secret')
    expect(sipIssues).toContain(CRYPTO_INTEGRITY_ISSUE.sipIdentity)
    expect(resolveCryptographicIntegrity({ issues: sipIssues })).toBe('MODIFIED')
  })

  it('sanitizes multipart SIP body: SDP structured, other parts masked', () => {
    const boundary = 'bound123'
    const sdp = 'v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n'
    const secretPart = 'SECRET_ISV_PAYLOAD_SHOULD_VANISH'
    const body =
      `--${boundary}\r\n`
      + 'Content-Type: application/sdp\r\n\r\n'
      + sdp
      + `\r\n--${boundary}\r\n`
      + 'Content-Type: application/octet-stream\r\n\r\n'
      + secretPart
      + `\r\n--${boundary}--\r\n`
    const buf = latin1([
      'INVITE sip:b@c SIP/2.0\r\n',
      'From: <sip:a@c>;tag=t\r\n',
      'To: <sip:b@c>\r\n',
      'Call-ID: mp@c\r\n',
      'CSeq: 1 INVITE\r\n',
      `Content-Type: multipart/mixed; boundary=${boundary}\r\n`,
      `Content-Length: ${body.length}\r\n\r\n`,
      body,
    ].join(''))

    const pkt = buildEthIpUdp([192, 168, 1, 1], [10, 0, 0, 2], 5060, 5060, buf)
    const mapping = new SessionMapping(DEFAULT_MAPPING_CONFIG)
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    expect(result.coverage.some((c) => c.protocol === 'sip-multipart' || c.protocol === 'sip')).toBe(true)
    const out = apply(pkt, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text).not.toContain(secretPart)
    // Dialog graph preserved: SIP request line still present
    expect(text).toContain('INVITE sip:')
    expect(result.drop).toBe(false)
  })
})

describe('enterprise step 8 — RTP telephone-event DTMF', () => {
  it('collects telephone-event payload types from SDP rtpmap', () => {
    const text =
      'v=0\r\n'
      + 'o=- 1 1 IN IP4 10.0.0.1\r\n'
      + 's=-\r\n'
      + 'c=IN IP4 10.0.0.1\r\n'
      + 't=0 0\r\n'
      + 'm=audio 4000 RTP/AVP 0 101\r\n'
      + 'a=rtpmap:0 PCMU/8000\r\n'
      + 'a=rtpmap:101 telephone-event/8000\r\n'
    const buf = latin1(text)
    const parsed = parseSdp(buf, 0, buf.length)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const pts = collectTelephoneEventPayloadTypes(
      buf,
      parsed.session.sessionAttributes,
      parsed.session.media[0]!.attributes,
    )
    expect([...pts]).toEqual([101])
    const eps = buildSdpMediaEndpoints(parsed.session, buf)
    expect(eps[0]?.telephoneEventPayloadTypes).toEqual([101])
  })

  it('diagnostic masks DTMF digits; high-privacy drops telephone-event packet', () => {
    const mediaPort = 5004
    const sdp =
      'v=0\r\n'
      + 'o=- 1 1 IN IP4 192.168.1.10\r\n'
      + 's=-\r\n'
      + 'c=IN IP4 192.168.1.10\r\n'
      + 't=0 0\r\n'
      + `m=audio ${mediaPort} RTP/AVP 0 101\r\n`
      + 'a=rtpmap:101 telephone-event/8000\r\n'
      + `a=rtcp:${mediaPort + 1}\r\n`
    const sip = latin1([
      'INVITE sip:bob@10.0.0.2 SIP/2.0\r\n',
      'From: <sip:alice@192.168.1.10>;tag=t1\r\n',
      'To: <sip:bob@10.0.0.2>\r\n',
      'Call-ID: dtmf-dialog@host\r\n',
      'CSeq: 1 INVITE\r\n',
      'Content-Type: application/sdp\r\n',
      `Content-Length: ${sdp.length}\r\n\r\n`,
      sdp,
    ].join(''))

    // RTP telephone-event PT=101, event digit '5' (0x05) in first payload byte
    const dtmf = new Uint8Array(12 + 4)
    dtmf[0] = 0x80
    dtmf[1] = 101
    dtmf[2] = 0x00
    dtmf[3] = 0x01
    dtmf.set([0x11, 0x22, 0x33, 0x44], 8) // SSRC
    dtmf[12] = 0x05 // digit 5
    dtmf[13] = 0x0a
    dtmf[14] = 0x00
    dtmf[15] = 0xa0

    const sipPkt = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, sip)
    const dtmfPkt = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort, 40000, dtmf)
    const mapping = new SessionMapping(DEFAULT_MAPPING_CONFIG)
    const mediaIndex = new MediaFlowIndex()

    // Register SDP endpoints via SIP sanitize path
    sanitizePacket(
      { index: 0, data: sipPkt, capturedLength: sipPkt.length, originalLength: sipPkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { mediaFlowIndex: mediaIndex },
    )

    const diag = sanitizePacket(
      { index: 1, data: dtmfPkt, capturedLength: dtmfPkt.length, originalLength: dtmfPkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { mediaFlowIndex: mediaIndex },
    )
    expect(diag.drop).toBe(false)
    expect(diag.issues).toContain(TELEPHONE_EVENT_ISSUE)
    const diagOut = apply(dtmfPkt, diag)
    const diagPayload = diagOut.subarray(14 + 20 + 8)
    expect(diagPayload[12]).not.toBe(0x05) // digit masked
    expect(diagPayload.length).toBe(dtmf.length) // packet count/length preserved

    const hpIndex = new MediaFlowIndex()
    sanitizePacket(
      { index: 0, data: sipPkt, capturedLength: sipPkt.length, originalLength: sipPkt.length, linkType: 1 },
      HIGH_PRIVACY_POLICY,
      mapping,
      { mediaFlowIndex: hpIndex },
    )
    const hp = sanitizePacket(
      { index: 1, data: dtmfPkt, capturedLength: dtmfPkt.length, originalLength: dtmfPkt.length, linkType: 1 },
      HIGH_PRIVACY_POLICY,
      mapping,
      { mediaFlowIndex: hpIndex },
    )
    expect(hp.drop).toBe(true)
    expect(hp.issues).toContain(TELEPHONE_EVENT_ISSUE)
  })
})
