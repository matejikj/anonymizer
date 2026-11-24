/**
 * T47 — TLS ServerHello / ClientHello field privacy contract.
 *
 * Field decision (synthetic offsets relative to Hello *body*, after handshake header):
 * | Offset | Field              | Decision                                      |
 * |--------|--------------------|-----------------------------------------------|
 * | 0..2   | legacy_version     | preserve (negotiation / structure)            |
 * | 2..34  | random(32)         | mask (legacy GMT + session correlator)        |
 * | 34     | session_id_len     | preserve                                      |
 * | 35..   | session_id         | mask                                          |
 * | …      | cipher / compr.    | preserve (negotiation facts)                  |
 * | …      | ext type+length    | preserve                                      |
 * | …      | known meta ext     | preserve value (supported_versions, ALPN, …)  |
 * | …      | unknown / key_share| mask value                                    |
 *
 * Root cause of the prior 47 B unchanged window: coverage marked the whole
 * record+ServerHello `covered` while random(32)+framing stayed identical. Product
 * now masks random; the privacy oracle allowlists only structural ranges above.
 *
 * @vitest-environment node
 */

import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import {
  assertNoUnchangedWindow,
  tlsHelloStructuralPreserveRanges,
} from '../helpers/privacyLeakScan'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'

function buildEthIpTcp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const tcpHeaderLen = 20
  const total = 14 + 20 + tcpHeaderLen + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 0)
  buf.set([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotal = 20 + tcpHeaderLen + payload.length
  buf[16] = (ipTotal >> 8) & 0xff
  buf[17] = ipTotal & 0xff
  buf[23] = 6
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  const tcpOff = 34
  buf[tcpOff] = (srcPort >> 8) & 0xff
  buf[tcpOff + 1] = srcPort & 0xff
  buf[tcpOff + 2] = (dstPort >> 8) & 0xff
  buf[tcpOff + 3] = dstPort & 0xff
  buf[tcpOff + 12] = 0x50
  buf[tcpOff + 13] = 0x18
  buf.set(payload, 14 + 20 + tcpHeaderLen)
  return buf
}

function wrapHandshake(messages: number[]): Uint8Array {
  return new Uint8Array([
    0x16, 0x03, 0x03,
    (messages.length >> 8) & 0xff, messages.length & 0xff,
    ...messages,
  ])
}

/** ServerHello with canary random + empty session id + optional unknown extension. */
function buildServerHello(opts: {
  readonly randomFill?: number
  readonly sessionId?: number[]
  readonly unknownExtPayload?: number[]
}): number[] {
  const random = new Array(32).fill(opts.randomFill ?? 0xa5)
  const sid = opts.sessionId ?? []
  let body = [0x03, 0x03, ...random, sid.length, ...sid, 0xc0, 0x2f, 0x00]
  if (opts.unknownExtPayload) {
    const payload = opts.unknownExtPayload
    const ext = [0xfe, 0x00, (payload.length >> 8) & 0xff, payload.length & 0xff, ...payload]
    body = [...body, (ext.length >> 8) & 0xff, ext.length & 0xff, ...ext]
  }
  return [0x02, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body]
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function envelope(data: Uint8Array, index: number): PacketEnvelope {
  return {
    index,
    packetNumber: index + 1,
    data,
    capturedLength: data.length,
    originalLength: data.length,
    timestamp: { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0 },
    linkType: 1,
  }
}

describe('T47 TLS ServerHello privacy', () => {
  for (const level of ['diagnostic', 'high-privacy'] as const) {
    const policy = level === 'diagnostic' ? DIAGNOSTIC_POLICY : HIGH_PRIVACY_POLICY

    it(`masks server_random under ${level}`, () => {
      const randomFill = 0xb7
      const sh = buildServerHello({ randomFill })
      const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 443, 40000, wrapHandshake(sh))
      const result = sanitizePacket(
        { index: 0, data: frame, capturedLength: frame.length, originalLength: frame.length, linkType: 1 },
        policy,
        new SessionMapping(undefined, { seed: `t47-random-${level}` }),
      )
      expect(result.coverage.some((c) => c.protocol === 'tls-serverhello' && c.status === 'covered')).toBe(true)
      const out = applyPatches(frame, result)
      const tlsOff = 54
      const randomOff = tlsOff + 5 + 4 + 2 // record + hs hdr + version
      const origRandom = frame.slice(randomOff, randomOff + 32)
      const outRandom = out.slice(randomOff, randomOff + 32)
      expect([...origRandom]).toEqual(new Array(32).fill(randomFill))
      expect([...outRandom]).not.toEqual([...origRandom])
      // legacy version + cipher preserved
      expect(out[tlsOff + 5 + 4]).toBe(0x03)
      expect(out[tlsOff + 5 + 4 + 1]).toBe(0x03)
    })

    it(`masks session_id and unknown extension canaries under ${level}`, () => {
      const sessionId = Array.from('SIDCANARY47T47XXXX', (c) => c.charCodeAt(0))
      const unknown = Array.from('UNK-EXT-CANARY-T47', (c) => c.charCodeAt(0))
      const sh = buildServerHello({ sessionId, unknownExtPayload: unknown })
      const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 443, 40001, wrapHandshake(sh))
      const result = sanitizePacket(
        { index: 0, data: frame, capturedLength: frame.length, originalLength: frame.length, linkType: 1 },
        policy,
        new SessionMapping(undefined, { seed: `t47-sid-${level}` }),
      )
      const out = applyPatches(frame, result)
      const text = Buffer.from(out).toString('latin1')
      expect(text).not.toContain('SIDCANARY47T47XXXX')
      expect(text).not.toContain('UNK-EXT-CANARY-T47')
    })
  }

  it('export pipeline: structural allowlist + no non-structural unchanged window', () => {
    const sh = buildServerHello({ randomFill: 0x22 })
    const frame = buildEthIpTcp([10, 0, 0, 2], [93, 184, 216, 34], 443, 55123, wrapHandshake(sh))
    const packets = [envelope(frame, 0)]
    const exported = runExportPipeline(packets, 'diagnostic', 't47.pcap', 't47', { mappingSeed: 't47-export-seed' })
    const out = readClassicPcap(exported.built.buffer).packets[0]!.data
    const span = exported.discovery.packetDiscovery[0]!.coverage.find((c) => c.protocol === 'tls-serverhello')
    expect(span).toBeTruthy()
    const allowed = tlsHelloStructuralPreserveRanges(frame, span!, 'server')
    assertNoUnchangedWindow(frame, out, span!, 8, 't47-sh', allowed)
    // Attack variant of the historical 47 B window: random must differ.
    const randomOff = 54 + 5 + 4 + 2
    expect([...out.slice(randomOff, randomOff + 32)]).not.toEqual([...frame.slice(randomOff, randomOff + 32)])
  })

  it('preserves supported_versions negotiation while masking key_share-like unknown', () => {
    // supported_versions (0x002b) value 03 04 stays; unknown fe00 payload masked.
    const random = new Array(32).fill(0x11)
    const sv = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
    const unk = [0xfe, 0x01, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]
    const exts = [...sv, ...unk]
    const body = [0x03, 0x03, ...random, 0x00, 0xc0, 0x2f, 0x00, (exts.length >> 8) & 0xff, exts.length & 0xff, ...exts]
    const sh = [0x02, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body]
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 443, 40002, wrapHandshake(sh))
    const result = sanitizePacket(
      { index: 0, data: frame, capturedLength: frame.length, originalLength: frame.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 't47-sv-preserve' }),
    )
    const out = applyPatches(frame, result)
    expect([...out]).toContain(0x03)
    // selected TLS 1.3 bytes from supported_versions value should remain
    const outText = Buffer.from(out).toString('hex')
    expect(outText).toContain('002b00020304')
    expect(outText).not.toContain('deadbeef')
  })
})
