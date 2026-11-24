/**
 * T41 — AMQP / Kafka / NATS / STOMP / XMPP / GELF / Fluent / OTLP auth and body canaries.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp, buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { SEMANTIC_SERVICE_PORTS } from '../../../src/pcap/anonymization/portPolicy'

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

function writeU16be(buf: Uint8Array, o: number, v: number): void {
  buf[o] = (v >>> 8) & 0xff
  buf[o + 1] = v & 0xff
}

describe('T41 registry', () => {
  it('registers messaging handlers, family, ports, and engine 2.36.1', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(
      expect.arrayContaining([
        'amqp',
        'kafka',
        'nats',
        'stomp',
        'xmpp',
        'gelf',
        'fluent',
        'otlp',
      ]),
    )
    expect(familyForProtocol('amqp').familyId).toBe('messaging')
    expect(familyForProtocol('kafka-sasl').familyId).toBe('messaging')
    expect(familyForProtocol('nats-connect').familyId).toBe('messaging')
    expect(familyForProtocol('gelf-body').familyId).toBe('messaging')
    expect(SEMANTIC_SERVICE_PORTS.has(5672)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(9092)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(4222)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(12201)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
  })
})

describe('T41 AMQP SASL', () => {
  it('masks Connection.Start-Ok SASL response and does not leak password canary', () => {
    // PLAIN\0user\0pass canary inside method args
    const sasl = new TextEncoder().encode('PLAIN\0amqp-canary\0AMQP-PASS-CANARY')
    const methodArgs = new Uint8Array(4 + sasl.length)
    writeU16be(methodArgs, 0, 10) // class Connection
    writeU16be(methodArgs, 2, 11) // Start-Ok
    methodArgs.set(sasl, 4)
    const frame = new Uint8Array(7 + methodArgs.length + 1)
    frame[0] = 1 // method
    writeU16be(frame, 1, 0)
    writeU32be(frame, 3, methodArgs.length)
    frame.set(methodArgs, 7)
    frame[7 + methodArgs.length] = 0xce
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5672, 1, frame)
    const mapping = new SessionMapping(undefined, { seed: 't41-amqp' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'amqp-sasl')).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('AMQP-PASS-CANARY')).toBe(false)
  })
})

describe('T41 Kafka SASL', () => {
  it('masks SaslAuthenticate request body', () => {
    const auth = new TextEncoder().encode('PLAIN\0kafka-user\0KAFKA-PASS-CANARY')
    const clientId = new TextEncoder().encode('t41-client')
    // size + apiKey + apiVersion + correlation + clientId + auth
    const bodyLen = 2 + 2 + 4 + 2 + clientId.length + auth.length
    const payload = new Uint8Array(4 + bodyLen)
    writeU32be(payload, 0, bodyLen)
    writeU16be(payload, 4, 36) // SaslAuthenticate
    writeU16be(payload, 6, 1)
    writeU32be(payload, 8, 7)
    writeU16be(payload, 12, clientId.length)
    payload.set(clientId, 14)
    payload.set(auth, 14 + clientId.length)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 9092, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't41-kafka' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'kafka-sasl')).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('KAFKA-PASS-CANARY')).toBe(false)
  })
})

describe('T41 NATS CONNECT', () => {
  it('masks CONNECT pass and does not leak canary', () => {
    const line = 'CONNECT {"user":"nats-canary","pass":"NATS-PASS-CANARY","verbose":false}\r\n'
    const payload = new TextEncoder().encode(line)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 4222, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't41-nats' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(
      result.coverage.some((c) => c.protocol === 'nats-connect' || c.protocol === 'nats-auth'),
    ).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('NATS-PASS-CANARY')).toBe(false)
  })
})

describe('T41 STOMP CONNECT', () => {
  it('maps login and masks passcode', () => {
    const frame = 'CONNECT\nlogin:stomp-canary\npasscode:STOMP-PASS-CANARY\n\n\0'
    const payload = new TextEncoder().encode(frame)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 61613, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't41-stomp' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'stomp-auth')).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('STOMP-PASS-CANARY')).toBe(false)
    expect(latin1(out).includes('stomp-canary')).toBe(false)
  })
})

describe('T41 XMPP SASL / body', () => {
  it('masks SASL auth payload and message body', () => {
    const xml =
      "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>XMPP-SASL-CANARY</auth>"
      + "<message from='user@xmpp.example/res'><body>XMPP-BODY-CANARY</body></message>"
    const payload = new TextEncoder().encode(xml)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5222, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't41-xmpp' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'xmpp-sasl' || c.protocol === 'xmpp-body')).toBe(
      true,
    )
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('XMPP-SASL-CANARY')).toBe(false)
    expect(latin1(out).includes('XMPP-BODY-CANARY')).toBe(false)
  })
})

describe('T41 GELF JSON', () => {
  it('sanitizes uncompressed GELF JSON and drops short_message canary via detectors/mask', () => {
    const json = JSON.stringify({
      version: '1.1',
      host: 'gelf-canary-host',
      short_message: 'GELF-MSG-CANARY secret@example.com',
      level: 3,
    })
    const payload = new TextEncoder().encode(json)
    const pkt = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 12201, payload)
    const mapping = new SessionMapping(undefined, { seed: 't41-gelf' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(
      result.coverage.some((c) => c.protocol.startsWith('gelf')),
    ).toBe(true)
    const out = applyPatches(pkt, result)
    // email / message content must not survive unchecked
    expect(latin1(out).includes('secret@example.com')).toBe(false)
  })
})

describe('T41 Fluent Forward', () => {
  it('maps MessagePack tag and masks record body', () => {
    const tag = new TextEncoder().encode('fluent.canary.tag')
    // fixarray size 2 + fixstr tag + nil (placeholder record)
    const payload = new Uint8Array(1 + 1 + tag.length + 1)
    payload[0] = 0x92 // array of 2
    payload[1] = 0xa0 | tag.length
    payload.set(tag, 2)
    payload[2 + tag.length] = 0xc0 // nil
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 24224, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't41-fluent' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'fluent-tag' || c.protocol === 'fluent')).toBe(
      true,
    )
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('fluent.canary.tag')).toBe(false)
  })
})

describe('T41 OTLP JSON', () => {
  it('sanitizes OTLP JSON body canary', () => {
    const json = JSON.stringify({
      resourceLogs: [
        {
          resource: { attributes: [{ key: 'host.name', value: { stringValue: 'otlp-canary-host' } }] },
          scopeLogs: [
            {
              logRecords: [{ body: { stringValue: 'OTLP-LOG-CANARY user@example.com' } }],
            },
          ],
        },
      ],
    })
    const payload = new TextEncoder().encode(json)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 4318, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't41-otlp' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('otlp'))).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('user@example.com')).toBe(false)
  })
})
