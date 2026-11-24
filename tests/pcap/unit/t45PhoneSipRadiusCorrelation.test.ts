/**
 * T45 — same E.164 in SIP P-Asserted-Identity (tel:) and RADIUS Calling-Station-Id → one sip-phone alias.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { canonicalizeIdentity } from '../../../src/mapping/canonicalize'

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

function radiusCallingStation(value: string): Uint8Array {
  const val = new TextEncoder().encode(value)
  const pkt = new Uint8Array(20 + 2 + val.length)
  pkt[0] = 1
  pkt[1] = 42
  const total = pkt.length
  pkt[2] = (total >> 8) & 0xff
  pkt[3] = total & 0xff
  pkt[20] = 31 // Calling-Station-Id
  pkt[21] = 2 + val.length
  pkt.set(val, 22)
  return pkt
}

describe('T45 phone cross-protocol PCAP', () => {
  it('SIP tel: and RADIUS Calling-Station-Id share sip-phone alias on one SessionMapping', () => {
    const e164 = '+420777123456'
    const sipBody = [
      'INVITE sip:trunk@10.0.0.2 SIP/2.0',
      'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-t45',
      `P-Asserted-Identity: <tel:${e164}>`,
      'From: <sip:anon@10.0.0.1>;tag=t45',
      'To: <sip:b@10.0.0.2>',
      'Call-ID: t45-phone@host',
      'CSeq: 1 INVITE',
      'Content-Length: 0',
      '',
      '',
    ].join('\r\n')
    const sipPayload = new TextEncoder().encode(sipBody)
    const sipFrame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, sipPayload)

    const radiusPayload = radiusCallingStation(e164)
    const radiusFrame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1812, 1812, radiusPayload)

    const mapping = new SessionMapping(undefined, { seed: 't45-sip-radius' })
    sanitizePacket(packetInput(sipFrame), DIAGNOSTIC_POLICY, mapping)
    sanitizePacket(packetInput(radiusFrame), DIAGNOSTIC_POLICY, mapping)

    const canon = canonicalizeIdentity('sip-phone', e164)!
    const alias = mapping.get('sip-phone', canon)
    expect(alias).toBeTruthy()
    expect(alias).not.toContain('777')

    const sipOut = applyPatches(
      sipFrame,
      sanitizePacket(packetInput(sipFrame), DIAGNOSTIC_POLICY, mapping),
    )
    const radiusOut = applyPatches(
      radiusFrame,
      sanitizePacket(packetInput(radiusFrame), DIAGNOSTIC_POLICY, mapping),
    )
    expect(new TextDecoder('latin1').decode(sipOut)).not.toContain('777123456')
    expect(new TextDecoder('latin1').decode(radiusOut)).not.toContain('777123456')
  })
})
