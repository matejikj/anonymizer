/**
 * T63 / F1 — status↔mask canary: injected identity canaries must not survive sanitize.
 */

import { describe, expect, it } from 'vitest'
import {
  findSurvivingCanaries,
  injectFieldPolicyCanaries,
} from '../../../src/pcap/conformance'
import {
  ETHERNET_FIELD_POLICY,
  IPV4_FIELD_POLICY,
} from '../../../src/pcap/protocols/fieldPolicy/structural.ts'
import {
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  sanitizePacket,
} from '../../../src/pcap/sanitize'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import type { PacketInput } from '../../../src/pcap/sanitize'

function buildEthIpv4Udp(): Uint8Array {
  const payload = new Uint8Array([0x01, 0x02, 0x03, 0x04])
  const buf = new Uint8Array(14 + 20 + 8 + payload.length)
  buf.set([0xaa, 0x11, 0x22, 0x33, 0x44, 0x55], 0)
  buf.set([0xbb, 0x66, 0x77, 0x88, 0x99, 0xaa], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  buf[15] = 0x00
  const ipTotal = 20 + 8 + payload.length
  buf[16] = (ipTotal >> 8) & 0xff
  buf[17] = ipTotal & 0xff
  buf[18] = 0xab
  buf[19] = 0xcd // identification (mapped)
  buf[23] = 17
  buf.set([10, 20, 30, 40], 26)
  buf.set([10, 20, 30, 41], 30)
  buf[34] = 0x13
  buf[35] = 0xc4
  buf[36] = 0x00
  buf[37] = 0x35
  buf[38] = 0x00
  buf[39] = 8 + payload.length
  buf.set(payload, 42)
  return buf
}

function applyPatches(
  original: Uint8Array,
  patches: readonly { offset: number; data: Uint8Array }[],
): Uint8Array {
  const out = original.slice()
  for (const p of patches) out.set(p.data, p.offset)
  return out
}

describe('T63 canary conformance (structural L2/L3)', () => {
  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`${level}: ethernet/IPv4 identity canaries are absent after sanitize`, () => {
      const base = buildEthIpv4Udp()
      const eth = injectFieldPolicyCanaries({
        frame: base,
        protocolOffset: 0,
        fields: ETHERNET_FIELD_POLICY,
        level,
      })
      const withIp = injectFieldPolicyCanaries({
        frame: eth.frame,
        protocolOffset: 14,
        fields: IPV4_FIELD_POLICY,
        level,
      })
      const injected = [...eth.injected, ...withIp.injected]
      expect(injected.length).toBeGreaterThan(0)

      const mapping = new SessionMapping(undefined, { seed: `canary-${level}` })
      const policy = level === 'diagnostic' ? DIAGNOSTIC_POLICY : HIGH_PRIVACY_POLICY
      const frame = withIp.frame
      const input: PacketInput = {
        index: 0,
        data: frame,
        capturedLength: frame.length,
        originalLength: frame.length,
        linkType: 1,
      }
      const result = sanitizePacket(input, policy, mapping)
      const exported = applyPatches(frame, result.patches)
      const survivors = findSurvivingCanaries(exported, injected)
      expect(survivors).toEqual([])
    })
  }
})
