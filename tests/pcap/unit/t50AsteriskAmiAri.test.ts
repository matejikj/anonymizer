/**
 * T50 — Asterisk AMI / ARI canaries (Login secrets, channel IDs, api_key, path resources).
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

describe('T50 registry', () => {
  it('registers ami/ari handlers, family, ports, and engine 2.36.1', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('ami')
    expect(ids).toContain('ari')
    expect(ids.indexOf('ari')).toBeLessThan(ids.indexOf('http'))
    expect(familyForProtocol('ami').familyId).toBe('ami-ari')
    expect(familyForProtocol('ami-auth').familyId).toBe('ami-ari')
    expect(familyForProtocol('ari').familyId).toBe('ami-ari')
    expect(familyForProtocol('ari-json').familyId).toBe('ami-ari')
    expect(SEMANTIC_SERVICE_PORTS.has(5038)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(8088)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})

describe('T50 AMI Login and channel lifecycle', () => {
  it('masks Secret/Challenge and maps CallerID/Channel/Uniqueid/ActionID', () => {
    const ami = [
      'Asterisk Call Manager/2.10.4',
      'Action: Login',
      'Username: admin',
      'Secret: SUPER-SECRET-AMI-PASS',
      'ActionID: act-canary-001',
      '',
      'Event: DialBegin',
      'Privilege: call,all',
      'Channel: PJSIP/alice-00000001',
      'CallerIDNum: +420111222333',
      'CallerIDName: Alice Canary',
      'Uniqueid: 1700000000.1',
      'Linkedid: 1700000000.1',
      'DestChannel: PJSIP/bob-00000002',
      'BridgeUniqueid: bridge-canary-xyz',
      'Variable: CANARY_CTX=secret-value-leak',
      'Challenge: challenge-token-AABBCC',
      '',
    ].join('\r\n')
    const payload = new TextEncoder().encode(ami)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5038, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't50-ami' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('ami'))).toBe(true)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('SUPER-SECRET-AMI-PASS')).toBe(false)
    expect(out.includes('challenge-token-AABBCC')).toBe(false)
    expect(out.includes('secret-value-leak')).toBe(false)
    expect(out.includes('+420111222333')).toBe(false)
    expect(out.includes('PJSIP/alice-00000001')).toBe(false)
    expect(out.includes('act-canary-001')).toBe(false)
    expect(out.includes('bridge-canary-xyz')).toBe(false)
    // Structural keys preserved
    expect(out.includes('Action: Login')).toBe(true)
    expect(out.includes('Event: DialBegin')).toBe(true)
  })

  it('masks CLI lines that inject fake Event: keys', () => {
    const ami = [
      'Response: Follows',
      'Privilege: Command',
      'ActionID: cli-1',
      'Output: Event: FakeLeak',
      'Message: Complete',
      '',
    ].join('\r\n')
    const payload = new TextEncoder().encode(ami)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5038, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't50-cli' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('FakeLeak')).toBe(false)
  })
})

describe('T50 ARI HTTP', () => {
  it('masks api_key, maps path channel id, and remaps JSON caller number', () => {
    const body = JSON.stringify({
      id: 'channel-canary-99',
      name: 'PJSIP/alice-00000001',
      caller: { name: 'Alice', number: '+420444555666' },
      bridge: 'bridge-canary-ari',
      media_uri: 'sound:private/recording-canary.wav',
    })
    const req = [
      'POST /ari/channels/channel-canary-99/answer?api_key=ARI-API-KEY-CANARY HTTP/1.1',
      'Host: pbx.example.com:8088',
      'Content-Type: application/json',
      `Content-Length: ${body.length}`,
      '',
      body,
    ].join('\r\n')
    const payload = new TextEncoder().encode(req)
    const pkt = buildEthIpTcp([192, 0, 2, 10], [192, 0, 2, 20], 50_000, 8088, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't50-ari' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('ari'))).toBe(true)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('ARI-API-KEY-CANARY')).toBe(false)
    expect(out.includes('+420444555666')).toBe(false)
    expect(out.includes('private/recording-canary.wav')).toBe(false)
    expect(out.includes('channel-canary-99')).toBe(false)
    expect(out.includes('POST /ari/channels/')).toBe(true)
  })

  it('does not claim generic HTTP without /ari/ path', () => {
    const req = [
      'GET /health HTTP/1.1',
      'Host: pbx.example.com:8088',
      '',
      '',
    ].join('\r\n')
    const payload = new TextEncoder().encode(req)
    const pkt = buildEthIpTcp([192, 0, 2, 10], [192, 0, 2, 20], 50_000, 8088, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't50-non-ari' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'ari')).toBe(false)
  })
})
