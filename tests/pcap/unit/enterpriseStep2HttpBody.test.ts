/**
 * Enterprise step 2 — fail-closed HTTP body (structured JSON iff exact wire length, else MASK).
 */

import { describe, expect, it } from 'vitest'
import { sanitizePacket, type PacketInput } from '../../../src/pcap/sanitize'
import { DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/profile/presets'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { findJsonStringSpans } from '../../../src/pcap/sanitize/httpBody'
import { IntentCollector } from '../../../src/pcap/discovery/intentCollector'

function latin1(s: string): Uint8Array {
  return new Uint8Array(Array.from(s, (c) => c.charCodeAt(0)))
}

function buildEthIpTcp(
  src: number[],
  dst: number[],
  sport: number,
  dport: number,
  payload: Uint8Array,
): Uint8Array {
  const eth = new Uint8Array(14)
  eth[12] = 0x08
  eth[13] = 0x00
  const ipLen = 20 + 20 + payload.length
  const ip = new Uint8Array(20)
  ip[0] = 0x45
  ip[2] = (ipLen >> 8) & 0xff
  ip[3] = ipLen & 0xff
  ip[8] = 64
  ip[9] = 6
  ip.set(src, 12)
  ip.set(dst, 16)
  const tcp = new Uint8Array(20)
  tcp[0] = (sport >> 8) & 0xff
  tcp[1] = sport & 0xff
  tcp[2] = (dport >> 8) & 0xff
  tcp[3] = dport & 0xff
  tcp[12] = 0x50
  tcp[13] = 0x18
  const out = new Uint8Array(14 + 20 + 20 + payload.length)
  out.set(eth, 0)
  out.set(ip, 14)
  out.set(tcp, 34)
  out.set(payload, 54)
  return out
}

function exportBytes(pkt: Uint8Array, result: { patches: { offset: number; data: Uint8Array }[]; truncatedLength?: number }): Uint8Array {
  const len = result.truncatedLength ?? pkt.length
  const out = pkt.slice(0, len)
  for (const patch of result.patches) {
    if (patch.offset < len) {
      out.set(patch.data.subarray(0, Math.min(patch.data.length, len - patch.offset)), patch.offset)
    }
  }
  return out
}

function httpPacket(headersAndBody: string): { input: PacketInput; pkt: Uint8Array } {
  const payload = latin1(headersAndBody)
  const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 54321, 80, payload)
  return {
    pkt,
    input: {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    },
  }
}

describe('enterprise step 2 — HTTP body fail-closed', () => {
  it('maps phone in application/json body with exact packet length (diagnostic)', () => {
    const phone = '+420777123456'
    const body = `{"caller":"${phone}","status":"ok"}`
    const text =
      `POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n` +
      `Content-Length: ${body.length}\r\n\r\n${body}`
    const { input, pkt } = httpPacket(text)
    const mapping = new SessionMapping()
    const intents = new IntentCollector()
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping, { intents })

    expect(result.drop).toBe(false)
    expect(result.truncatedLength).toBeUndefined()
    expect(exportBytes(pkt, result).length).toBe(pkt.length)

    const bodyCov = result.coverage.find((c) => c.protocol === 'http-body')
    expect(bodyCov?.status).toBe('covered')

    const out = new TextDecoder('ascii', { fatal: false }).decode(exportBytes(pkt, result))
    expect(out).not.toContain(phone)
    expect(out).toContain('"status":"ok"')
    expect(out).toMatch(/"caller":"\+?\d{9,15}"/)
    expect(intents.intents.some((i) => i.kind === 'entity-replacement')).toBe(true)
  })

  it('masks secret JSON fields and removes token plaintext', () => {
    const token = 'sk_live_SUPERSECRETTOKEN99'
    const body = `{"token":"${token}","n":1}`
    const text =
      `POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n` +
      `Content-Length: ${body.length}\r\n\r\n${body}`
    const { input, pkt } = httpPacket(text)
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping())
    const out = new TextDecoder('ascii', { fatal: false }).decode(exportBytes(pkt, result))
    expect(out).not.toContain(token)
    expect(out).not.toContain('SUPERSECRET')
    expect(exportBytes(pkt, result).length).toBe(pkt.length)
  })

  it('MASKs gzip Content-Encoding body in place (never decompress)', () => {
    const secret = 'CANARY-GZIP-BODY-SECRET'
    // Pretend compressed body bytes (not valid gzip — we must not try to parse).
    const body = latin1(secret)
    const header =
      `POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n` +
      `Content-Encoding: gzip\r\nContent-Length: ${body.length}\r\n\r\n`
    const payload = new Uint8Array(header.length + body.length)
    payload.set(latin1(header), 0)
    payload.set(body, header.length)
    const pkt = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, payload)
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    }
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping())
    expect(result.truncatedLength).toBeUndefined()
    expect(exportBytes(pkt, result).length).toBe(pkt.length)
    const bodyCov = result.coverage.find((c) => c.protocol === 'http-body')
    expect(bodyCov?.status).toBe('redacted')
    const out = new TextDecoder('ascii', { fatal: false }).decode(exportBytes(pkt, result))
    expect(out).not.toContain(secret)
  })

  it('MASKs unknown Content-Type body (no leave-as-is) for both profiles', () => {
    const secret = 'CANARY-UNKNOWN-BODY-42'
    const text =
      `POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/octet-stream\r\n` +
      `Content-Length: ${secret.length}\r\n\r\n${secret}`
    const { input, pkt } = httpPacket(text)

    for (const policy of [DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY]) {
      const result = sanitizePacket(input, policy, new SessionMapping())
      expect(result.drop).toBe(false)
      // Step 2: TCP stream body → MASK preferred (length preserved) for both profiles.
      expect(result.truncatedLength).toBeUndefined()
      expect(exportBytes(pkt, result).length).toBe(pkt.length)
      const bodyCov = result.coverage.find((c) => c.protocol === 'http-body')
      expect(bodyCov?.status).toBe('redacted')
      const out = new TextDecoder('ascii', { fatal: false }).decode(exportBytes(pkt, result))
      expect(out).not.toContain(secret)
    }
  })

  it('MASKs malformed JSON instead of passthrough', () => {
    const secret = '+420777999888'
    const body = `{"caller":"${secret}"` // missing closing
    const text =
      `POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n` +
      `Content-Length: ${body.length}\r\n\r\n${body}`
    const { input, pkt } = httpPacket(text)
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping())
    expect(result.coverage.find((c) => c.protocol === 'http-body')?.status).toBe('redacted')
    expect(new TextDecoder('ascii', { fatal: false }).decode(exportBytes(pkt, result))).not.toContain(secret)
  })
})

describe('enterprise step 2 — JSON string span finder', () => {
  it('finds object string values with preceding keys', () => {
    const body = latin1('{"caller":"+420777123456","status":"ok"}')
    const spans = findJsonStringSpans(body, 100)
    expect(spans).not.toBeNull()
    expect(spans!.map((s) => ({ v: s.value, k: s.precedingKey }))).toEqual([
      { v: '+420777123456', k: 'caller' },
      { v: 'ok', k: 'status' },
    ])
    expect(spans![0]!.absOffset).toBe(100 + '{"caller":"'.length)
  })

  it('inherits enclosing key for array string items', () => {
    const body = latin1('{"privateValues":["AUDIT_ARRAY_SECRET_77319"]}')
    const spans = findJsonStringSpans(body, 0)
    expect(spans).not.toBeNull()
    expect(spans!).toEqual([
      expect.objectContaining({
        value: 'AUDIT_ARRAY_SECRET_77319',
        precedingKey: 'privateValues',
      }),
    ])
  })
})
