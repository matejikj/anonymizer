/**
 * T49 — CSTA / uaCSTA canaries (Annex J, MakeCall identities, secrets, uaCSTA SIP).
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { sanitizeCsta } from '../../../src/pcap/sanitize/csta'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { planSipBodyOperations } from '../../../src/pcap/protocols/application/sip/bodyOperations'
import { parseSipMessages } from '../../../src/pcap/protocols/application/sip/parser'
import {
  cstaMonitorGraphForTransport,
  resetCstaMonitorGraphsForTests,
} from '../../../src/pcap/sanitize/csta/cstaMonitorGraph'
import {
  disposeProtocolGraphStateForSession,
  protocolGraphCaptureGeneration,
  tcpTransportSessionKey,
} from '../../../src/pcap/sanitize/protocolGraphState'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { assertCaptureHasNoPrivacyLeaks } from '../helpers/privacyLeakScan'

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

function writeU32be(buf: Uint8Array, o: number, v: number): void {
  buf[o] = (v >>> 24) & 0xff
  buf[o + 1] = (v >>> 16) & 0xff
  buf[o + 2] = (v >>> 8) & 0xff
  buf[o + 3] = v & 0xff
}

const MAKE_CALL_XML = [
  '<?xml version="1.0"?>',
  '<MakeCall xmlns="http://www.ecma-international.org/standards/ecma-323/csta/ed6">',
  '<callingDevice>tel:+420111222333</callingDevice>',
  '<calledDirectoryNumber>tel:+420444555666</calledDirectoryNumber>',
  '<callID>CALL-ID-CANARY-001</callID>',
  '<userData>SECRET-USER-DATA-CANARY</userData>',
  '<digits>1234</digits>',
  '</MakeCall>',
].join('')

describe('T49 registry', () => {
  it('registers csta handler, family, and engine 2.36.1', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('csta')
    expect(familyForProtocol('csta').familyId).toBe('csta')
    expect(familyForProtocol('csta-xml').familyId).toBe('csta')
    expect(familyForProtocol('sip-csta').familyId).toBe('csta')
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})

describe('T49 Annex J MakeCall', () => {
  it('masks secrets and original device/call identities', () => {
    const xml = new TextEncoder().encode(MAKE_CALL_XML)
    const payload = new Uint8Array(4 + xml.length)
    writeU32be(payload, 0, xml.length)
    payload.set(xml, 4)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 8882, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't49-csta' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('csta'))).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('SECRET-USER-DATA-CANARY')).toBe(false)
    expect(latin1(out).includes('420111222333')).toBe(false)
    expect(latin1(out).includes('CALL-ID-CANARY-001')).toBe(false)
    // Annex J length prefix preserved (first 4 bytes of TCP payload)
    const start = 14 + 20 + 20
    expect(out[start]).toBe(payload[0])
    expect(out[start + 1]).toBe(payload[1])
    expect(out[start + 2]).toBe(payload[2])
    expect(out[start + 3]).toBe(payload[3])
  })
})

describe('T49 XXE reject', () => {
  it('fail-closed masks DOCTYPE payloads', () => {
    const xml = new TextEncoder().encode(
      '<!DOCTYPE MakeCall [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><MakeCall>&xxe;</MakeCall>',
    )
    const payload = new Uint8Array(4 + xml.length)
    writeU32be(payload, 0, xml.length)
    payload.set(xml, 4)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 8882, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't49-xxe' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.issues.some((i) => i.includes('xxe') || i.includes('csta-xxe'))).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('file:///etc/passwd')).toBe(false)
  })
})

describe('T49 uaCSTA SIP body', () => {
  it('does not merge CSTA callID across two SIP Call-IDs (uaCSTA scope)', () => {
    const sharedCallId = 'SHARED-CSTA-CALL-UA-0099'
    const cstaXml = [
      '<?xml version="1.0"?>',
      '<MakeCall xmlns="http://www.ecma-international.org/standards/ecma-323/csta/ed6">',
      `<callID>${sharedCallId}</callID>`,
      '<callingDevice>tel:+420111222333</callingDevice>',
      '</MakeCall>',
    ].join('')
    const mapping = new SessionMapping(undefined, { seed: 't49-uacsta-scope' })
    const buildInvite = (callId: string) => {
      const headers = [
        'INVITE sip:ua@example.com SIP/2.0',
        'Via: SIP/2.0/UDP 192.0.2.1:5060',
        'From: <sip:a@example.com>;tag=1',
        'To: <sip:b@example.com>',
        `Call-ID: ${callId}`,
        'CSeq: 1 INVITE',
        'Content-Type: application/csta+xml',
        `Content-Length: ${cstaXml.length}`,
      ]
      return new TextEncoder().encode(`${headers.join('\r\n')}\r\n\r\n${cstaXml}`)
    }
    const pktA = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5060, 1, buildInvite('sip-dialog-a'))
    const pktB = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_001, 5060, 1, buildInvite('sip-dialog-b'))
    sanitizePacket(packetInput(pktA), DIAGNOSTIC_POLICY, mapping)
    sanitizePacket({ ...packetInput(pktB), index: 1 }, DIAGNOSTIC_POLICY, mapping)
    const aliasA = mapping.get('opaque-id', `csta-call:uacsta:sip:sip-dialog-a:${sharedCallId}`)
    const aliasB = mapping.get('opaque-id', `csta-call:uacsta:sip:sip-dialog-b:${sharedCallId}`)
    expect(aliasA).toBeDefined()
    expect(aliasB).toBeDefined()
    expect(aliasA).not.toBe(aliasB)
  })

  it('plans sip-csta coverage for application/csta+xml', () => {
    const body = MAKE_CALL_XML
    const headers = [
      'INVITE sip:ua@example.com SIP/2.0',
      'Via: SIP/2.0/UDP 192.0.2.1:5060',
      'From: <sip:a@example.com>;tag=1',
      'To: <sip:b@example.com>',
      'Call-ID: sip-call-id-separate',
      'CSeq: 1 INVITE',
      'Content-Type: application/csta+xml',
      `Content-Length: ${body.length}`,
    ]
    const buf = new TextEncoder().encode(`${headers.join('\r\n')}\r\n\r\n${body}`)
    const stream = parseSipMessages(buf)
    expect(stream.messages.length).toBe(1)
    const message = stream.messages[0]!.message
    const plan = planSipBodyOperations(message, buf)
    expect(plan.coverage.some((c) => c.protocol === 'sip-csta')).toBe(true)
    expect(plan.operations.some((o) => o.action === 'redact')).toBe(true)
  })
})

describe('T49 ASN.1 mask-only', () => {
  it('masks BER-like CSTA without claiming structured decode', () => {
    // Minimal SEQUENCE with opaque content canary
    const canary = new TextEncoder().encode('ASN1-CSTA-CANARY!!!!')
    const ber = new Uint8Array(2 + canary.length)
    ber[0] = 0x30
    ber[1] = canary.length
    ber.set(canary, 2)
    const collector = new PatchCollector(ber.length)
    const mapping = new SessionMapping(undefined, { seed: 't49-asn1' })
    const result = sanitizeCsta(ber, 0, ber.length, 0, 0, collector, mapping, 0, false)
    expect(result).not.toBeNull()
    expect(result!.coverage.some((c) => c.protocol === 'csta-asn1')).toBe(true)
    const out = ber.slice()
    for (const p of collector.getPatches()) out.set(p.data, p.offset)
    expect(latin1(out).includes('ASN1-CSTA-CANARY')).toBe(false)
  })
})

describe('T49 MonitorStart/Stop lifecycle (XML)', () => {
  const transport = tcpTransportSessionKey({
    srcIp: '192.0.2.1',
    dstIp: '192.0.2.2',
    srcPort: 40_000,
    dstPort: 8882,
  })

  beforeEach(() => resetCstaMonitorGraphsForTests())

  it('reuses monitorCrossRef alias when event precedes MonitorStartResponse', () => {
    const mapping = new SessionMapping(undefined, { seed: 't49-mon-order' })
    const scope = 'csta:192.0.2.1:40000>192.0.2.2:8882'
    const crossRef = 'MON-LIFECYCLE-XREF-771'
    const eventXml = [
      '<?xml version="1.0"?>',
      '<DeliveredEvent xmlns="http://www.ecma-international.org/standards/ecma-323/csta/ed6">',
      `<monitorCrossRefID>${crossRef}</monitorCrossRefID>`,
      '<callID>CALL-MON-LC-771</callID>',
      '</DeliveredEvent>',
    ].join('')
    const responseXml = [
      '<?xml version="1.0"?>',
      '<MonitorStartResponse xmlns="http://www.ecma-international.org/standards/ecma-323/csta/ed6">',
      `<monitorCrossRefID>${crossRef}</monitorCrossRefID>`,
      '<invokeID>7</invokeID>',
      '</MonitorStartResponse>',
    ].join('')
    const pktEvent = buildEthIpTcp(
      [192, 0, 2, 1],
      [192, 0, 2, 2],
      40_000,
      8882,
      1,
      new TextEncoder().encode(eventXml),
    )
    const pktResp = buildEthIpTcp(
      [192, 0, 2, 1],
      [192, 0, 2, 2],
      40_000,
      8882,
      1,
      new TextEncoder().encode(responseXml),
    )
    sanitizePacket(packetInput(pktEvent), DIAGNOSTIC_POLICY, mapping)
    sanitizePacket({ ...packetInput(pktResp), index: 1 }, DIAGNOSTIC_POLICY, mapping)
    const aliasEvent = mapping.get('opaque-id', `csta-monitor:${scope}:${crossRef}`)
    expect(aliasEvent).toBeDefined()
    const graph = cstaMonitorGraphForTransport(mapping, transport)
    expect(graph.isMonitorActive(crossRef)).toBe(true)
    expect(graph.getFacts().some((f) => f.kind === 'monitor-event')).toBe(true)
  })

  it('keeps two monitorCrossRef IDs distinct on one transport', () => {
    const mapping = new SessionMapping(undefined, { seed: 't49-two-mon' })
    const scope = 'csta:192.0.2.1:40000>192.0.2.2:8882'
    const start = (crossRef: string, device: string) =>
      [
        '<?xml version="1.0"?>',
        '<MonitorStart xmlns="http://www.ecma-international.org/standards/ecma-323/csta/ed6">',
        `<monitorCrossRefID>${crossRef}</monitorCrossRefID>`,
        `<deviceID>${device}</deviceID>`,
        '</MonitorStart>',
      ].join('')
    sanitizePacket(
      packetInput(
        buildEthIpTcp(
          [192, 0, 2, 1],
          [192, 0, 2, 2],
          40_000,
          8882,
          1,
          new TextEncoder().encode(start('MON-A-002', 'DEV-SHARED-002')),
        ),
      ),
      DIAGNOSTIC_POLICY,
      mapping,
    )
    sanitizePacket(
      {
        ...packetInput(
          buildEthIpTcp(
            [192, 0, 2, 1],
            [192, 0, 2, 2],
            40_000,
            8882,
            1,
            new TextEncoder().encode(start('MON-B-002', 'DEV-SHARED-002')),
          ),
        ),
        index: 1,
      },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    const aliasA = mapping.get('opaque-id', `csta-monitor:${scope}:MON-A-002`)
    const aliasB = mapping.get('opaque-id', `csta-monitor:${scope}:MON-B-002`)
    expect(aliasA).toBeDefined()
    expect(aliasB).toBeDefined()
    expect(aliasA).not.toBe(aliasB)
  })

  it('does not merge invokeID after session dispose (reconnect generation)', () => {
    const mapping = new SessionMapping(undefined, { seed: 't49-invoke-reuse' })
    const scope = 'csta:192.0.2.1:40000>192.0.2.2:8882'
    const gen0 = protocolGraphCaptureGeneration()
    const invokeXml = [
      '<?xml version="1.0"?>',
      '<MonitorStart xmlns="http://www.ecma-international.org/standards/ecma-323/csta/ed6">',
      '<invokeID>INVOKE-REUSE-01</invokeID>',
      '<deviceID>DEV-INVOKE-REUSE</deviceID>',
      '</MonitorStart>',
    ].join('')
    sanitizePacket(
      packetInput(
        buildEthIpTcp(
          [192, 0, 2, 1],
          [192, 0, 2, 2],
          40_000,
          8882,
          1,
          new TextEncoder().encode(invokeXml),
        ),
      ),
      DIAGNOSTIC_POLICY,
      mapping,
    )
    const aliasGen0 = mapping.get('opaque-id', `csta-invoke:${scope}:${gen0}:INVOKE-REUSE-01`)
    disposeProtocolGraphStateForSession()
    const gen1 = protocolGraphCaptureGeneration()
    expect(gen1).not.toBe(gen0)
    sanitizePacket(
      {
        ...packetInput(
          buildEthIpTcp(
            [192, 0, 2, 1],
            [192, 0, 2, 2],
            40_000,
            8882,
            1,
            new TextEncoder().encode(invokeXml),
          ),
        ),
        index: 1,
      },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    const aliasGen1 = mapping.get('opaque-id', `csta-invoke:${scope}:${gen1}:INVOKE-REUSE-01`)
    expect(aliasGen0).toBeDefined()
    expect(aliasGen1).toBeDefined()
    expect(aliasGen0).not.toBe(aliasGen1)
  })
})

describe('T49 CSTA monitor export regression', () => {
  beforeEach(() => resetCstaMonitorGraphsForTests())

  const CANARY_SECRET = 'EXPORT-MON-USERDATA-001'

  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`export pipeline masks monitor lifecycle secrets (${level})`, () => {
      const xml = [
        '<?xml version="1.0"?>',
        '<MonitorStart xmlns="http://www.ecma-international.org/standards/ecma-323/csta/ed6">',
        '<monitorCrossRefID>MON-EXPORT-001</monitorCrossRefID>',
        '<deviceID>tel:+420111222333</deviceID>',
        `<userData>${CANARY_SECRET}</userData>`,
        '</MonitorStart>',
      ].join('')
      const payload = new Uint8Array(4 + xml.length)
      writeU32be(payload, 0, xml.length)
      payload.set(new TextEncoder().encode(xml), 4)
      const pkt = buildEthIpTcp(
        [192, 0, 2, 1],
        [192, 0, 2, 2],
        40_000,
        8882,
        1,
        payload,
      )
      const exported = runExportPipeline(
        [
          {
            packetNumber: 1,
            timestamp: { ticks: 1n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
            capturedLength: pkt.length,
            originalLength: pkt.length,
            linkType: 1,
            interfaceId: 0,
            sectionIndex: 0,
            fileOffset: 0,
            data: pkt,
          },
        ],
        level,
        't49-monitor-export.pcap',
        `t49-monitor-export-${level}`,
        { mappingSeed: `t49-monitor-export-${level}` },
      )
      const wire = latin1(exported.built.packets[0]!.data)
      expect(wire.includes(CANARY_SECRET)).toBe(false)
      expect(wire.includes('420111222333')).toBe(false)
      assertCaptureHasNoPrivacyLeaks(exported.built.packets, [CANARY_SECRET, '420111222333'])
    })
  }
})

describe('T49 PBX transport scope (MonitorStart AC — negative merge)', () => {
  const SHARED_CALL_ID = 'SHARED-PBX-CALL-0099'
  const sharedCallXml = [
    '<?xml version="1.0"?>',
    '<MakeCall xmlns="http://www.ecma-international.org/standards/ecma-323/csta/ed6">',
    `<callID>${SHARED_CALL_ID}</callID>`,
    '<callingDevice>tel:+420111222333</callingDevice>',
    '</MakeCall>',
  ].join('')

  it('does not merge identical callID aliases across two TCP PBX flows', () => {
    const mapping = new SessionMapping(undefined, { seed: 't49-pbx-scope' })
    const body = new TextEncoder().encode(sharedCallXml)
    const pktA = buildEthIpTcp([192, 0, 10, 1], [192, 0, 10, 2], 40_000, 8882, 1, body)
    const pktB = buildEthIpTcp([192, 0, 20, 1], [192, 0, 20, 2], 41_000, 8882, 1, body)
    sanitizePacket(packetInput(pktA), DIAGNOSTIC_POLICY, mapping)
    sanitizePacket({ ...packetInput(pktB), index: 1 }, DIAGNOSTIC_POLICY, mapping)
    const scopeA = 'csta:192.0.10.1:40000>192.0.10.2:8882'
    const scopeB = 'csta:192.0.20.1:41000>192.0.20.2:8882'
    const aliasA = mapping.get('opaque-id', `csta-call:${scopeA}:${SHARED_CALL_ID}`)
    const aliasB = mapping.get('opaque-id', `csta-call:${scopeB}:${SHARED_CALL_ID}`)
    expect(aliasA).toBeDefined()
    expect(aliasB).toBeDefined()
    expect(aliasA).not.toBe(aliasB)
  })
})

describe('T49 V03 privateData / attrs / vendor (both levels)', () => {
  const xml = [
    '<MakeCall xmlns="urn:ecma:csta" privateAttr="AUDIT_XML_ATTRIBUTE_77319">',
    '<callingDevice>123456789</callingDevice>',
    '<vendorToken>AUDIT_XML_EXTENSION_77319</vendorToken>',
    '<privateData><vendorField>AUDIT_XML_NESTED_SECRET_77319</vendorField></privateData>',
    '</MakeCall>',
  ].join('')
  const canaries = [
    'AUDIT_XML_ATTRIBUTE_77319',
    'AUDIT_XML_EXTENSION_77319',
    'AUDIT_XML_NESTED_SECRET_77319',
  ] as const

  for (const policy of [DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY]) {
    it(`masks attribute, vendor element, and nested privateData (${policy.preset})`, () => {
      const pkt = buildEthIpTcp(
        [192, 0, 2, 1],
        [192, 0, 2, 2],
        40_000,
        40_001,
        1,
        new TextEncoder().encode(xml),
      )
      const mapping = new SessionMapping(undefined, { seed: `t49-v03-${policy.preset}` })
      const result = sanitizePacket(packetInput(pkt), policy, mapping)
      expect(result.coverage.some((c) => c.protocol.startsWith('csta'))).toBe(true)
      const out = latin1(applyPatches(pkt, result))
      for (const c of canaries) {
        expect(out.includes(c)).toBe(false)
      }
      expect(out.includes('123456789')).toBe(false)
      expect(out.includes('MakeCall')).toBe(true)
    })
  }
})
