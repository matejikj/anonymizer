/**
 * T55 — CWMP SOAP / USP Record canaries (credentials, serial, endpoint ids).
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { SEMANTIC_SERVICE_PORTS } from '../../../src/pcap/anonymization/portPolicy'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
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

function encodeVarint(v: number): Uint8Array {
  const bytes: number[] = []
  let x = v >>> 0
  while (x >= 0x80) {
    bytes.push((x & 0x7f) | 0x80)
    x >>>= 7
  }
  bytes.push(x)
  return Uint8Array.from(bytes)
}

function pbTag(field: number, wt: number): Uint8Array {
  return encodeVarint((field << 3) | wt)
}

function pbString(field: number, s: string): Uint8Array {
  const data = new TextEncoder().encode(s)
  return concat(pbTag(field, 2), encodeVarint(data.length), data)
}

function pbVarintField(field: number, v: number): Uint8Array {
  return concat(pbTag(field, 0), encodeVarint(v))
}

function pbEmbedded(field: number, inner: Uint8Array): Uint8Array {
  return concat(pbTag(field, 2), encodeVarint(inner.length), inner)
}

describe('T55 registry', () => {
  it('registers cwmp/usp handlers, family, ports, and engine 2.36.1', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('cwmp')
    expect(ids).toContain('usp')
    expect(ids.indexOf('cwmp')).toBeLessThan(ids.indexOf('http'))
    expect(familyForProtocol('cwmp').familyId).toBe('cwmp-usp')
    expect(familyForProtocol('usp-id').familyId).toBe('cwmp-usp')
    expect(SEMANTIC_SERVICE_PORTS.has(7547)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})

describe('T55 CWMP Inform', () => {
  it('maps SerialNumber/ID; masks Password and secret ParameterValue; preserves Inform RPC', () => {
    const soap = [
      '<?xml version="1.0"?>',
      '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">',
      '<soap:Header><cwmp:ID soap:mustUnderstand="1">ID-CANARY-991</cwmp:ID></soap:Header>',
      '<soap:Body><cwmp:Inform>',
      '<DeviceId>',
      '<Manufacturer>AcmeCorp</Manufacturer>',
      '<OUI>AABBCC</OUI>',
      '<ProductClass>RouterX</ProductClass>',
      '<SerialNumber>SN-CANARY-DEVICE-42</SerialNumber>',
      '</DeviceId>',
      '<ParameterList soap-enc:arrayType="cwmp:ParameterValueStruct[2]">',
      '<ParameterValueStruct>',
      '<Name>Device.ManagementServer.Username</Name>',
      '<Value>acs-user-canary</Value>',
      '</ParameterValueStruct>',
      '<ParameterValueStruct>',
      '<Name>Device.ManagementServer.Password</Name>',
      '<Value>SECRET-CWMP-PASS-CANARY</Value>',
      '</ParameterValueStruct>',
      '</ParameterList>',
      '</cwmp:Inform></soap:Body></soap:Envelope>',
    ].join('')
    const http = [
      'POST /cwmp HTTP/1.1',
      'Host: acs.example.com',
      'Content-Type: text/xml; charset=utf-8',
      `Content-Length: ${soap.length}`,
      '',
      soap,
    ].join('\r\n')
    const payload = new TextEncoder().encode(http)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 7547, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't55-cwmp' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('cwmp'))).toBe(true)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('Inform')).toBe(true)
    expect(out.includes('SN-CANARY-DEVICE-42')).toBe(false)
    expect(out.includes('ID-CANARY-991')).toBe(false)
    expect(out.includes('SECRET-CWMP-PASS-CANARY')).toBe(false)
    expect(out.includes('acs-user-canary')).toBe(false)
  })

  it('masks Download URL credentials and rejects XXE', () => {
    const soap = [
      '<?xml version="1.0"?>',
      '<soap:Envelope xmlns:cwmp="urn:dslforum-org:cwmp-1-0">',
      '<soap:Body><cwmp:Download>',
      '<CommandKey>DL-KEY-1</CommandKey>',
      '<URL>http://fw.example.com/img.bin?token=URL-TOKEN-CANARY</URL>',
      '<Username>dl-user</Username>',
      '<Password>DL-PASS-CANARY</Password>',
      '</cwmp:Download></soap:Body></soap:Envelope>',
    ].join('')
    const http = [
      'POST / HTTP/1.1',
      'Host: cpe.local',
      'Content-Type: application/soap+xml',
      `Content-Length: ${soap.length}`,
      '',
      soap,
    ].join('\r\n')
    const pkt = buildEthIpTcp(
      [192, 0, 2, 2],
      [192, 0, 2, 1],
      7547,
      40_000,
      1,
      new TextEncoder().encode(http),
    )
    const mapping = new SessionMapping(undefined, { seed: 't55-dl' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('URL-TOKEN-CANARY')).toBe(false)
    expect(out.includes('DL-PASS-CANARY')).toBe(false)
    expect(out.includes('Download')).toBe(true)

    const xxe = '<!DOCTYPE x [<!ENTITY e "leak">]><soap:Envelope xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><soap:Body><cwmp:Inform>&e;</cwmp:Inform></soap:Body></soap:Envelope>'
    const httpXxe = [
      'POST / HTTP/1.1',
      'Host: x',
      'Content-Type: text/xml',
      `Content-Length: ${xxe.length}`,
      '',
      xxe,
    ].join('\r\n')
    const pkt2 = buildEthIpTcp(
      [192, 0, 2, 1],
      [192, 0, 2, 2],
      40_001,
      7547,
      2,
      new TextEncoder().encode(httpXxe),
    )
    const result2 = sanitizePacket(packetInput(pkt2), DIAGNOSTIC_POLICY, mapping)
    expect(result2.issues.some((i) => i.includes('xxe'))).toBe(true)
    expect(latin1(applyPatches(pkt2, result2)).includes('ENTITY')).toBe(false)
  })
})

describe('T55 V06 CWMP CDATA password / vendor (both levels)', () => {
  const soap = [
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-4">',
    '<soap:Body><cwmp:SetParameterValues><ParameterList>',
    '<ParameterValueStruct>',
    '<Name>Device.ManagementServer.Password</Name>',
    '<Value><![CDATA[AUDIT_CWMP_PASSWORD_77319]]></Value>',
    '</ParameterValueStruct>',
    '</ParameterList>',
    '<vendorField>AUDIT_CWMP_EXTENSION_77319</vendorField>',
    '</cwmp:SetParameterValues></soap:Body></soap:Envelope>',
  ].join('')

  for (const policy of [DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY]) {
    it(`masks CDATA password and vendor extension (${policy.preset})`, () => {
      const pkt = buildEthIpTcp(
        [192, 0, 2, 1],
        [192, 0, 2, 2],
        40_000,
        7547,
        1,
        new TextEncoder().encode(soap),
      )
      const mapping = new SessionMapping(undefined, { seed: `t55-v06-${policy.preset}` })
      const result = sanitizePacket(packetInput(pkt), policy, mapping)
      expect(result.coverage.some((c) => c.protocol.startsWith('cwmp'))).toBe(true)
      const out = latin1(applyPatches(pkt, result))
      expect(out.includes('AUDIT_CWMP_PASSWORD_77319')).toBe(false)
      expect(out.includes('AUDIT_CWMP_EXTENSION_77319')).toBe(false)
      expect(out.includes('SetParameterValues')).toBe(true)
      expect(out.includes('Device.ManagementServer.Password')).toBe(true)
    })
  }
})

describe('T55 USP Record', () => {
  it('maps from_id/to_id; masks secret strings in plaintext Msg payload', () => {
    const msg = concat(
      pbString(1, 'msg-CANARY-99'),
      pbString(2, 'Device.LocalAgent.Controller.1.EndpointID'),
      pbString(3, 'SECRET-USP-PASSWORD-CANARY'),
    )
    const noSession = pbEmbedded(1, msg) // payload
    const record = concat(
      pbString(1, '1.0'),
      pbString(2, 'proto::controller-CANARY'),
      pbString(3, 'os::agent-CANARY-EP'),
      pbVarintField(4, 0), // PLAINTEXT
      pbEmbedded(7, noSession),
    )
    const pkt = buildEthIpTcp([192, 0, 2, 10], [192, 0, 2, 20], 50_000, 1883, 1, record)
    // Bare USP on MQTT port (MTP without MQTT framing) — mqtt.ts defers to USP
    const mapping = new SessionMapping(undefined, { seed: 't55-usp' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('usp'))).toBe(true)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('controller-CANARY')).toBe(false)
    expect(out.includes('agent-CANARY-EP')).toBe(false)
    expect(out.includes('SECRET-USP-PASSWORD-CANARY')).toBe(false)
    // version preserved
    expect(out.includes('1.0')).toBe(true)
  })

  it('masks non-plaintext payload_security body', () => {
    const secretPayload = new TextEncoder().encode('E2E-CIPHERTEXT-CANARY-VISIBLE')
    const noSession = concat(pbTag(1, 2), encodeVarint(secretPayload.length), secretPayload)
    const record = concat(
      pbString(1, '1.1'),
      pbString(2, 'to-ep'),
      pbString(3, 'from-ep'),
      pbVarintField(4, 1), // TLS / non-plaintext
      pbEmbedded(7, noSession),
    )
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 18_883, 1, record)
    const mapping = new SessionMapping(undefined, { seed: 't55-e2e' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('E2E-CIPHERTEXT-CANARY-VISIBLE')).toBe(false)
    expect(result.issues.some((i) => i.includes('non-plaintext'))).toBe(true)
  })
})
