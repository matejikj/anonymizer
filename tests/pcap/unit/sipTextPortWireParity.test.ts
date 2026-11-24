/**
 * SIP/SDP text ports must use the same transport-qualified identity (`udp/<n>`) as discovery
 * and the wire header: the journal map op once keyed them as bare digits, so every text port
 * fell back to a field mask with a `mapping-alias-missing` incident, and PCAP text ports were
 * aliased by the text-log engine (all 4-digit non-catalog ports → the same value, and a
 * preserved signaling port rewritten in the header while kept on the wire).
 * Synthetic packets only.
 */

import { describe, expect, it } from 'vitest'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { buildEthIpUdp, envelope } from '../fixtures/voipCorpus'

const SIP_PORT = 5070
const CONTACT_PORT = 5092
const MEDIA_PORT = 11464

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

function inviteOn5070(): Uint8Array {
  const sdp = ['v=0', 'o=- 1 2 IN IP4 192.0.2.10', 'c=IN IP4 192.0.2.10', `m=audio ${MEDIA_PORT} RTP/AVP 0`].join('\r\n')
  const sip = [
    'INVITE sip:bob@example.invalid SIP/2.0',
    `Via: SIP/2.0/UDP 192.0.2.10:${SIP_PORT};branch=z9hG4bKparity`,
    'From: <sip:alice@example.invalid>;tag=parity',
    'To: <sip:bob@example.invalid>',
    'Call-ID: parity-call-id@example.invalid',
    `Contact: <sip:alice@192.0.2.10:${CONTACT_PORT}>`,
    'Content-Type: application/sdp',
    `Content-Length: ${sdp.length}`,
  ].join('\r\n')
  return buildEthIpUdp([192, 0, 2, 10], [192, 0, 2, 20], SIP_PORT, SIP_PORT, latin1(`${sip}\r\n\r\n${sdp}`))
}

function textPort(payload: string, re: RegExp): number {
  const m = payload.match(re)
  expect(m, `pattern ${re}`).not.toBeNull()
  return Number.parseInt(m![1]!, 10)
}

describe('SIP/SDP text port ↔ wire parity', () => {
  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`${level}: text ports map without incidents and agree with the UDP header`, () => {
      const result = runExportPipeline([envelope(inviteOn5070(), 0)], level, 'parity.pcap', `parity-${level}`, {
        mappingSeed: `sip-text-port-parity-${level}`,
      })
      expect(result.plan.incidents?.totalFailures ?? 0).toBe(0)

      const out = readClassicPcap(result.built.buffer).packets[0]!.data
      const udpSrc = (out[34]! << 8) | out[35]!
      const payload = new TextDecoder('latin1').decode(out.subarray(42))

      const viaPort = textPort(payload, /Via: SIP\/2\.0\/UDP [^:\r\n]+:(\d+);/)
      const contactPort = textPort(payload, /Contact: <sip:[^@]+@[^:>]+:(\d+)>/)
      const mediaPort = textPort(payload, /m=audio (\d+) /)

      // The Via sent-by port is the UDP source port: it must agree with the wire alias whenever
      // that alias fits the original digit slot (ADR-2: length-preserving text may otherwise
      // carry a different representation of the same identity).
      if (String(udpSrc).length === String(SIP_PORT).length) expect(viaPort).toBe(udpSrc)
      // Distinct original ports keep distinct aliases (no shared text placeholder).
      expect(contactPort).not.toBe(viaPort)
      expect(mediaPort).not.toBe(contactPort)
      if (level === 'diagnostic') {
        // Content-signaling SIP port is preserved on the wire in diagnostic — and in text.
        expect(udpSrc).toBe(SIP_PORT)
        expect(viaPort).toBe(SIP_PORT)
      } else {
        // High-privacy permutes the non-catalog signaling port on the wire and in text.
        expect(udpSrc).not.toBe(SIP_PORT)
        expect(viaPort).not.toBe(SIP_PORT)
      }
      expect(udpSrc).not.toBe(0)
    })
  }
})
