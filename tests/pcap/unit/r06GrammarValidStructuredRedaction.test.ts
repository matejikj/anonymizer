/**
 * R06 — grammar-valid JSON/XML text redaction after export (no binary mask in text spans).
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { sanitizeSbi5g } from '../../../src/pcap/sanitize/sbi5g'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { parseBoundedXml } from '../../../src/pcap/protocols/application/csta/boundedXml'
import { buildEthIpTcp } from '../fixtures/voipCorpus'

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

function applyCollectorPatches(
  original: Uint8Array,
  collector: PatchCollector,
  mapping: SessionMapping,
): Uint8Array {
  collector.resolveDeferred({ mapping })
  const out = original.slice()
  for (const p of collector.getPatches()) out.set(p.data, p.offset)
  return out
}

function assertValidUtf8(bytes: Uint8Array): void {
  const dec = new TextDecoder('utf-8', { fatal: true })
  expect(() => dec.decode(bytes)).not.toThrow()
}

function tcpPayload(frame: Uint8Array): Uint8Array {
  return frame.subarray(54)
}

function httpBody(frame: Uint8Array): string {
  const payload = new TextDecoder('latin1').decode(tcpPayload(frame))
  const idx = payload.indexOf('\r\n\r\n')
  expect(idx).toBeGreaterThanOrEqual(0)
  return payload.slice(idx + 4)
}

const CANARY_KEY = 'AUDIT_DYNAMIC_KEY_77319'
const CANARY_VAL = 'AUDIT_DYNAMIC_VALUE_77319'

describe('R06 export-path structured syntax', () => {
  it('SBI bare JSON: JSON.parse succeeds; canaries gone; UTF-8 valid', () => {
    const body = JSON.stringify({
      supi: 'imsi-262019876543210',
      [CANARY_KEY]: CANARY_VAL,
      status: 'REGISTERED',
      rand: '00112233445566778899aabbccddeeff',
    })
    const raw = new TextEncoder().encode(body)
    const mapping = new SessionMapping(undefined, { seed: 'r06-sbi-bare' })
    const collector = new PatchCollector(raw.length)
    const result = sanitizeSbi5g(raw, 0, raw.length, collector, mapping, undefined, 0)
    expect(result?.coverage.some((c) => c.protocol === 'sbi5g-json')).toBe(true)
    const out = applyCollectorPatches(raw, collector, mapping)
    assertValidUtf8(out)
    const text = new TextDecoder('utf-8').decode(out)
    expect(text.includes(CANARY_KEY)).toBe(false)
    expect(text.includes(CANARY_VAL)).toBe(false)
    expect(text.includes('00112233445566778899aabbccddeeff')).toBe(false)
    const parsed = JSON.parse(text) as Record<string, unknown>
    expect(parsed.status).toBe('REGISTERED')
  })

  it('SBI HTTP/1.x Authorization header stays valid UTF-8 after export', () => {
    const token = 'AUDIT_BEARER_TOKEN_77319'
    const body = JSON.stringify({ status: 'REGISTERED' })
    const http = [
      'PUT /nnrf-nfm/v1/nf-instances/test HTTP/1.1',
      'Host: nrf.example.5gc',
      `Authorization: Bearer ${token}`,
      'Content-Type: application/json',
      `Content-Length: ${body.length}`,
      '',
      body,
    ].join('\r\n')
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 8080, 1, new TextEncoder().encode(http))
    const mapping = new SessionMapping(undefined, { seed: 'r06-sbi-auth' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const frame = applyPatches(pkt, result)
    assertValidUtf8(tcpPayload(frame))
    const text = new TextDecoder('utf-8').decode(tcpPayload(frame))
    expect(text.includes(token)).toBe(false)
  })

  it('SBI HTTP/1.x JSON body: JSON.parse after sanitizePacket export', () => {
    const body = JSON.stringify({
      nfInstanceId: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
      [CANARY_KEY]: CANARY_VAL,
      status: 'REGISTERED',
    })
    const http = [
      'PUT /nnrf-nfm/v1/nf-instances/test HTTP/1.1',
      'Host: nrf.example.5gc',
      'Content-Type: application/json',
      `Content-Length: ${body.length}`,
      '',
      body,
    ].join('\r\n')
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 8080, 1, new TextEncoder().encode(http))
    const mapping = new SessionMapping(undefined, { seed: 'r06-sbi-http' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const frame = applyPatches(pkt, result)
    assertValidUtf8(tcpPayload(frame))
    const jsonText = httpBody(frame)
    expect(jsonText.includes(CANARY_VAL)).toBe(false)
    const parsed = JSON.parse(jsonText) as Record<string, unknown>
    expect(parsed.status).toBe('REGISTERED')
  })

  it('CSTA XML: UTF-8 valid and bounded XML complete after export', () => {
    const xml = [
      '<MakeCall xmlns="urn:ecma:csta" privateAttr="AUDIT_XML_ATTRIBUTE_77319">',
      '<callingDevice>123456789</callingDevice>',
      '<privateData><vendorField>AUDIT_XML_NESTED_SECRET_77319</vendorField></privateData>',
      '</MakeCall>',
    ].join('')
    const pkt = buildEthIpTcp(
      [192, 0, 2, 1],
      [192, 0, 2, 2],
      40_000,
      40_001,
      1,
      new TextEncoder().encode(xml),
    )
    const mapping = new SessionMapping(undefined, { seed: 'r06-csta' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const payload = tcpPayload(applyPatches(pkt, result))
    assertValidUtf8(payload)
    const text = new TextDecoder('utf-8').decode(payload)
    expect(text.includes('AUDIT_XML_ATTRIBUTE_77319')).toBe(false)
    expect(text.includes('AUDIT_XML_NESTED_SECRET_77319')).toBe(false)
    expect(text.includes('123456789')).toBe(false)
    const parsed = parseBoundedXml(text)
    expect(parsed.complete).toBe(true)
    expect(parsed.issues.length).toBe(0)
  })

  it('CWMP SOAP: UTF-8 valid XML after CDATA password redaction', () => {
    const soap = [
      '<soap:Envelope xmlns:cwmp="urn:dslforum-org:cwmp-1-4">',
      '<soap:Body><cwmp:SetParameterValues><ParameterList>',
      '<ParameterValueStruct>',
      '<Name>Device.ManagementServer.Password</Name>',
      '<Value><![CDATA[AUDIT_CWMP_PASSWORD_77319]]></Value>',
      '</ParameterValueStruct>',
      '</ParameterList></cwmp:SetParameterValues></soap:Body></soap:Envelope>',
    ].join('')
    const pkt = buildEthIpTcp(
      [192, 0, 2, 1],
      [192, 0, 2, 2],
      40_000,
      7547,
      1,
      new TextEncoder().encode(soap),
    )
    const mapping = new SessionMapping(undefined, { seed: 'r06-cwmp' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const payload = tcpPayload(applyPatches(pkt, result))
    assertValidUtf8(payload)
    const text = new TextDecoder('utf-8').decode(payload)
    expect(text.includes('AUDIT_CWMP_PASSWORD_77319')).toBe(false)
    const parsed = parseBoundedXml(text)
    expect(parsed.complete).toBe(true)
  })
})
