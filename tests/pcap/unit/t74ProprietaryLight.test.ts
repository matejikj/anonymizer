/**
 * T74 — diagnostic proprietary-light anonymization; high-privacy stays truncate.
 */

import { describe, expect, it } from 'vitest'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector.ts'
import { createTestSessionMapping } from '../../../src/pcap/anonymization/testModeSeed.ts'
import {
  ProprietaryLightSession,
  sanitizeProprietaryLight,
} from '../../../src/pcap/sanitize/proprietaryLight/index.ts'
import { HIGH_PRIVACY_POLICY, DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets.ts'
import { FINAL_DISPOSITIONS } from '../../../src/pcap/export/dispositionLedger.ts'
import { PCAP_KERNEL_BUDGETS } from '../../../src/domain/capabilityContract.ts'

function payloadWithPrivateIp(): Uint8Array {
  // 8 B prefix + 10.1.2.3 + trailing counter bytes (stable structure)
  const buf = new Uint8Array(32)
  buf[0] = 0x01
  buf[1] = 0x02
  buf[8] = 10
  buf[9] = 1
  buf[10] = 2
  buf[11] = 3
  for (let i = 12; i < 32; i++) buf[i] = i & 0xff
  return buf
}

describe('T74 proprietary light', () => {
  it('exposes preserve-inferred disposition and diagnostic keeps unsupported as mask-in-place', () => {
    expect(FINAL_DISPOSITIONS).toContain('preserve-inferred')
    expect(DIAGNOSTIC_POLICY.unsupportedPayloadPolicy).toBe('mask-in-place')
    expect(HIGH_PRIVACY_POLICY.unsupportedPayloadPolicy).toBe('truncate')
  })

  it('fail-closes to redacted until cluster stats are ready', () => {
    const session = new ProprietaryLightSession()
    const mapping = createTestSessionMapping('t74-proprietary-light-seed')
    const buf = payloadWithPrivateIp()
    const collector = new PatchCollector(buf.length)
    const result = sanitizeProprietaryLight({
      buffer: buf,
      offset: 0,
      length: buf.length,
      collector,
      mapping,
      packetIndex: 0,
      session,
      flowKey: 'flow-a',
      senderKey: 'sender-a',
    })
    expect(result.coverage[0]?.status).toBe('redacted')
  })

  it('after enough messages maps private IPv4 and leaves structure', () => {
    const session = new ProprietaryLightSession()
    const mapping = createTestSessionMapping('t74-proprietary-light-seed-2')
    const buf = payloadWithPrivateIp()
    const min = PCAP_KERNEL_BUDGETS.proprietaryLightMinClusterMessages
    let last = sanitizeProprietaryLight({
      buffer: buf,
      offset: 0,
      length: buf.length,
      collector: new PatchCollector(buf.length),
      mapping,
      packetIndex: 0,
      session,
      flowKey: 'flow-b',
      senderKey: 'sender-b',
    })
    for (let i = 1; i < min + 2; i++) {
      // Vary trailing counter so cluster sees stable offsets.
      buf[31] = i & 0xff
      last = sanitizeProprietaryLight({
        buffer: buf,
        offset: 0,
        length: buf.length,
        collector: new PatchCollector(buf.length),
        mapping,
        packetIndex: i,
        session,
        flowKey: 'flow-b',
        senderKey: 'sender-b',
      })
    }
    // Rebuild one ready pass collecting patches — IPv4 10.1.2.3 must not remain.
    const collector = new PatchCollector(buf.length)
    buf[31] = 99
    const ready = sanitizeProprietaryLight({
      buffer: buf,
      offset: 0,
      length: buf.length,
      collector,
      mapping,
      packetIndex: 99,
      session,
      flowKey: 'flow-b',
      senderKey: 'sender-b',
    })
    expect(ready.coverage[0]?.status).toBeTruthy()
    expect(ready.coverage[0]?.status).not.toBe('unsupported')
    const out = buf.slice()
    for (const p of collector.getPatches()) {
      out.set(p.data, p.offset)
    }
    expect(out[8] === 10 && out[9] === 1 && out[10] === 2 && out[11] === 3).toBe(false)
    void last
  })
})
