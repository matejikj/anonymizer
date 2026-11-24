/**
 * T37 — MCPTT negative / revize-2026-10-17 corpus (vendor, role split, floor APP).
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { sanitizeRtcp } from '../../../src/pcap/sanitize/rtcp'
import { planSipBodyOperations } from '../../../src/pcap/protocols/application/sip/bodyOperations'
import { parseSipMessages } from '../../../src/pcap/protocols/application/sip/parser'
import { buildEthIpUdp } from '../fixtures/voipCorpus'

function buildSipBytes(headers: string[], body: string): Uint8Array {
  const all = [...headers, `Content-Length: ${body.length}`]
  return new TextEncoder().encode(`${all.join('\r\n')}\r\n\r\n${body}`)
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

describe('T37 MCPTT negative corpus', () => {
  it('redacts vendor extension element text and preserves request-type', () => {
    const xml =
      '<?xml version="1.0"?>\r\n'
      + '<mcptt-info>\r\n'
      + '<mcptt-request-type>private</mcptt-request-type>\r\n'
      + '<vendor-x-acme:secret-token>CANARY-VENDOR-991</vendor-x-acme:secret-token>\r\n'
      + '<mcptt-emergency-ind>false</mcptt-emergency-ind>\r\n'
      + '</mcptt-info>'
    const bytes = buildSipBytes(
      [
        'MESSAGE sip:g@example.com SIP/2.0',
        'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-mc-neg',
        'From: <sip:a@example.com>;tag=mcn1',
        'To: <sip:g@example.com>',
        'Call-ID: mcptt-neg-vendor',
        'CSeq: 1 MESSAGE',
        'Max-Forwards: 70',
        'Content-Type: application/vnd.3gpp.mcptt-info+xml',
      ],
      xml,
    )
    const message = parseSipMessages(bytes).messages[0]!.message
    const plan = planSipBodyOperations(message, bytes)
    expect(plan.operations.some((o) => o.action === 'redact' && o.canonicalText.includes('CANARY-VENDOR'))).toBe(
      true,
    )
    expect(plan.operations.some((o) => o.canonicalText === 'private')).toBe(false)

    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, bytes)
    const out = applyPatches(
      frame,
      sanitizePacket(
        { index: 0, data: frame, capturedLength: frame.length, originalLength: frame.length, linkType: 1 },
        DIAGNOSTIC_POLICY,
        new SessionMapping(undefined, { seed: 't37-mc-neg' }),
      ),
    )
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('CANARY-VENDOR-991')).toBe(false)
    expect(text.includes('private')).toBe(true)
    expect(text.includes('false')).toBe(true)
  })

  it('maps same URI localpart as user vs group with different categories', () => {
    const shared = 'sip:shared-role@example.com'
    const xml =
      '<?xml version="1.0"?>\r\n'
      + '<mcptt-info>\r\n'
      + `<mcptt-calling-user-id>${shared}</mcptt-calling-user-id>\r\n`
      + `<mcptt-calling-group-id>${shared}</mcptt-calling-group-id>\r\n`
      + '</mcptt-info>'
    const bytes = buildSipBytes(
      [
        'INVITE sip:g@example.com SIP/2.0',
        'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-mc-role',
        'From: <sip:a@example.com>;tag=mcn2',
        'To: <sip:g@example.com>',
        'Call-ID: mcptt-neg-role',
        'CSeq: 1 INVITE',
        'Max-Forwards: 70',
        'Content-Type: application/vnd.3gpp.mcptt-info+xml',
      ],
      xml,
    )
    const plan = planSipBodyOperations(parseSipMessages(bytes).messages[0]!.message, bytes)
    const userOp = plan.operations.find(
      (o) => o.action === 'map' && o.mappingCategory === 'sip-user' && o.canonicalText === shared,
    )
    const groupOp = plan.operations.find(
      (o) => o.action === 'map' && o.mappingCategory === 'hostname' && o.canonicalText === shared,
    )
    expect(userOp).toBeTruthy()
    expect(groupOp).toBeTruthy()
    expect(userOp!.span.offset).not.toBe(groupOp!.span.offset)
  })

  it('masks MCPT floor APP identity runs and maps granted SSRC', () => {
    const app = new Uint8Array(28)
    app[0] = 0x80
    app[1] = 204
    app[2] = 0x00
    app[3] = 0x06
    app.set([0x11, 0x22, 0x33, 0x44], 4)
    app.set([0x4d, 0x43, 0x50, 0x54], 8) // MCPT
    app[12] = 0x01
    app[13] = 0x02
    app.set([0xaa, 0xbb, 0xcc, 0xdd], 14) // granted SSRC
    app.set([0x55, 0x53, 0x45, 0x52, 0x2d, 0x43, 0x41, 0x4e], 18) // USER-CAN

    const collector = new PatchCollector(app.length)
    const mapping = new SessionMapping(undefined, { seed: 't37-mcpt-floor' })
    sanitizeRtcp(app, 0, app.length, collector, mapping, undefined, 0)
    collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
    const out = app.slice()
    for (const p of collector.getPatches()) out.set(p.data, p.offset)

    expect([...out.subarray(8, 12)]).toEqual([0x4d, 0x43, 0x50, 0x54])
    expect([...out.subarray(14, 18)]).not.toEqual([0xaa, 0xbb, 0xcc, 0xdd])
    expect(new TextDecoder('latin1').decode(out).includes('USER-CAN')).toBe(false)
  })
})
