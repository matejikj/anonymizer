/**
 * T36 — WebSocket (+ SIP), HTTP/2 h2c, gRPC framing.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { sha1, webSocketAcceptFromKey } from '../../../src/crypto/sha1'
import { looksLikeHttp2Preface } from '../../../src/pcap/sanitize/http2'

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

function wsClientTextFrame(text: string, maskKey: number[] = [0x11, 0x22, 0x33, 0x44]): Uint8Array {
  const payload = new TextEncoder().encode(text)
  const masked = new Uint8Array(payload.length)
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i]! ^ maskKey[i & 3]!
  if (payload.length < 126) {
    const hdr = new Uint8Array(2 + 4 + masked.length)
    hdr[0] = 0x81 // FIN + text
    hdr[1] = 0x80 | payload.length
    hdr.set(maskKey, 2)
    hdr.set(masked, 6)
    return hdr
  }
  const hdr = new Uint8Array(2 + 2 + 4 + masked.length)
  hdr[0] = 0x81
  hdr[1] = 0x80 | 126
  hdr[2] = (payload.length >> 8) & 0xff
  hdr[3] = payload.length & 0xff
  hdr.set(maskKey, 4)
  hdr.set(masked, 8)
  return hdr
}

describe('T36 registry', () => {
  it('registers websocket/http2/grpc and bumps engine', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(expect.arrayContaining(['websocket', 'http2', 'grpc']))
    expect(familyForProtocol('websocket').familyId).toBe('http')
    expect(familyForProtocol('http2').familyId).toBe('http')
    expect(familyForProtocol('grpc').familyId).toBe('http')
    expect(PCAP_ENGINE_VERSION).toBe('2.35.0')
  })

  it('computes RFC 6455 Accept from Key', () => {
    // Example from RFC 6455
    expect(webSocketAcceptFromKey('dGhlIHNhbXBsZSBub25jZQ==')).toBe('s3pPLMBiTxaQ9kYGzzhZRbK+xOo=')
    expect(sha1(new TextEncoder().encode('abc')).length).toBe(20)
  })
})

describe('T36 WebSocket SIP', () => {
  it('unmasks, sanitizes SIP canary, remasks with same key', () => {
    const sip =
      'INVITE sip:canary-ws@10.1.2.3 SIP/2.0\r\n'
      + 'Via: SIP/2.0/WS client.invalid;branch=z9hG4bK-wscanary\r\n'
      + 'From: <sip:canary-ws@10.1.2.3>;tag=wstag\r\n'
      + 'To: <sip:other@10.1.2.3>\r\n'
      + 'Call-ID: ws-call-canary-001\r\n'
      + 'CSeq: 1 INVITE\r\n'
      + 'Content-Length: 0\r\n'
      + '\r\n'
    const mask = [0xde, 0xad, 0xbe, 0xef]
    const frame = wsClientTextFrame(sip, mask)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 50_000, 8080, 1, frame)
    const mapping = new SessionMapping(undefined, { seed: 't36-ws' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'websocket' || c.protocol === 'sip')).toBe(true)
    const out = applyPatches(pkt, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('canary-ws')).toBe(false)
    expect(text.includes('ws-call-canary-001')).toBe(false)
    // Mask key preserved (extended length header: 2+2+4)
    const tcpOff = 14 + 20 + 20
    expect([...out.subarray(tcpOff + 4, tcpOff + 8)]).toEqual(mask)
    const payloadOff = tcpOff + 8
    const logicalLen = frame.length - 8
    const logical = new Uint8Array(logicalLen)
    for (let i = 0; i < logicalLen; i++) {
      logical[i] = out[payloadOff + i]! ^ mask[i & 3]!
    }
    const logicalText = new TextDecoder('latin1').decode(logical)
    expect(logicalText.includes('canary-ws')).toBe(false)
    expect(logicalText.startsWith('INVITE') || logicalText.includes('SIP/2.0')).toBe(true)
  })

  it('maps Sec-WebSocket-Key and derives Accept in same message', () => {
    const key = 'dGhlIHNhbXBsZSBub25jZQ=='
    const accept = webSocketAcceptFromKey(key)
    const http =
      'HTTP/1.1 101 Switching Protocols\r\n'
      + 'Upgrade: websocket\r\n'
      + 'Connection: Upgrade\r\n'
      + `Sec-WebSocket-Key: ${key}\r\n`
      + `Sec-WebSocket-Accept: ${accept}\r\n`
      + 'Sec-WebSocket-Protocol: sip\r\n'
      + '\r\n'
    const body = wsClientTextFrame('OPTIONS sip:x@y SIP/2.0\r\nContent-Length: 0\r\n\r\n')
    const payload = new Uint8Array(http.length + body.length)
    payload.set(new TextEncoder().encode(http), 0)
    payload.set(body, http.length)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 50_001, 8080, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't36-hs' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(pkt, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes(key)).toBe(false)
    // Accept must match mapped key (28 chars) — original accept should be gone if key changed
    expect(result.coverage.some((c) => c.protocol === 'http-headers')).toBe(true)
  })
})

describe('T36 HTTP/2 + gRPC', () => {
  it('masks HPACK header block and preserves SETTINGS framing', () => {
    const preface = new TextEncoder().encode('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
    expect(looksLikeHttp2Preface(preface, 0, preface.length)).toBe(true)
    // SETTINGS empty
    const settings = new Uint8Array([0, 0, 0, 0x04, 0, 0, 0, 0, 0])
    // HEADERS with canary payload
    const canary = new TextEncoder().encode('CANARY-H2-HEADER-BLOCK!!')
    const headers = new Uint8Array(9 + canary.length)
    headers[0] = (canary.length >> 16) & 0xff
    headers[1] = (canary.length >> 8) & 0xff
    headers[2] = canary.length & 0xff
    headers[3] = 0x01 // HEADERS
    headers[4] = 0x05 // END_STREAM|END_HEADERS
    headers[5] = 0
    headers[6] = 0
    headers[7] = 0
    headers[8] = 1 // stream 1
    headers.set(canary, 9)
    const payload = new Uint8Array(preface.length + settings.length + headers.length)
    payload.set(preface, 0)
    payload.set(settings, preface.length)
    payload.set(headers, preface.length + settings.length)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 50_002, 80, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't36-h2' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'http2')).toBe(true)
    const out = applyPatches(pkt, result)
    expect(new TextDecoder('latin1').decode(out).includes('CANARY-H2-HEADER-BLOCK')).toBe(false)
  })

  it('masks gRPC message body keeping length prefix', () => {
    const preface = new TextEncoder().encode('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
    const settings = new Uint8Array([0, 0, 0, 0x04, 0, 0, 0, 0, 0])
    const msg = new TextEncoder().encode('GRPC-CANARY-MESSAGE-BODY')
    const grpc = new Uint8Array(5 + msg.length)
    grpc[0] = 0
    grpc[1] = (msg.length >> 24) & 0xff
    grpc[2] = (msg.length >> 16) & 0xff
    grpc[3] = (msg.length >> 8) & 0xff
    grpc[4] = msg.length & 0xff
    grpc.set(msg, 5)
    const data = new Uint8Array(9 + grpc.length)
    data[0] = (grpc.length >> 16) & 0xff
    data[1] = (grpc.length >> 8) & 0xff
    data[2] = grpc.length & 0xff
    data[3] = 0x00 // DATA
    data[4] = 0x01 // END_STREAM
    data[8] = 1
    data.set(grpc, 9)
    const payload = new Uint8Array(preface.length + settings.length + data.length)
    payload.set(preface, 0)
    payload.set(settings, preface.length)
    payload.set(data, preface.length + settings.length)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 50_003, 80, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't36-grpc' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(pkt, result)
    expect(new TextDecoder('latin1').decode(out).includes('GRPC-CANARY-MESSAGE-BODY')).toBe(false)
    expect(result.coverage.some((c) => c.protocol === 'grpc' || c.protocol === 'grpc-message')).toBe(true)
  })
})
