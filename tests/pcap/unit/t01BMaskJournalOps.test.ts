/**
 * T-01.B — journal mask ops from maskRangeDeferred; freeze drops legacyResolve when fully symbolized.
 */
import { describe, expect, it } from 'vitest'
import { sanitizeDns } from '../../../src/pcap/sanitize/dns'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { IntentCollector } from '../../../src/pcap/discovery/intentCollector'
import { freezeSanitizationResult } from '../../../src/pcap/kernel/adapters/freezeDiscovery'
import { resolveFrozenPacketPlan } from '../../../src/pcap/kernel/frozenPlan'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { maskRangeDeferredProtocolNeutral } from '../../../src/pcap/sanitize/deferredMaskMeta'

function encodeDnsName(labels: string[]): number[] {
  const bytes: number[] = []
  for (const label of labels) {
    bytes.push(label.length)
    for (const ch of label) bytes.push(ch.charCodeAt(0))
  }
  bytes.push(0)
  return bytes
}

function txtSubrecord(value: string): number[] {
  return [value.length, ...Array.from(value, (c) => c.charCodeAt(0))]
}

/** One ANSWER RR with unknown TYPE — only QNAME map deferrals + journal-backed RDATA mask. */
function buildUnknownRdataAnswer(rdata: number[]): Uint8Array {
  const name = encodeDnsName(['host'])
  return new Uint8Array([
    0x00, 0x01,
    0x84, 0x00,
    0x00, 0x00,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    ...name,
    0x00, 0x99,
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c,
    (rdata.length >> 8) & 0xff,
    rdata.length & 0xff,
    ...rdata,
  ])
}

describe('T-01.B mask journal ops', () => {
  it('freezeSanitizationResult omits legacyResolve when deferrals are fully journal-backed', () => {
    const collector = new PatchCollector(64)
    maskRangeDeferredProtocolNeutral(
      collector,
      8,
      12,
      0,
      'dns-txt-value',
      'dns',
      'dns-txt-value',
    )
    expect(collector.isDeferredFullySymbolized()).toBe(true)

    const result = {
      packetIndex: 0,
      patches: collector.getPatches(),
      resolvePatches: (ctx: Parameters<PatchCollector['resolveDeferred']>[0]) => {
        collector.resolveDeferred(ctx)
        return collector.getPatches()
      },
      symbolicMapOps: collector.getSymbolicJournalOps(),
      deferredFullySymbolized: collector.isDeferredFullySymbolized(),
      coverage: [],
      drop: false,
      issues: [] as string[],
    }

    const frozen = freezeSanitizationResult({
      packetIndex: 0,
      packetNumber: 1,
      bufferLength: 64,
      result,
      intents: [],
    })
    expect(frozen.legacyResolve).toBeUndefined()
    expect(frozen.ops.some((o) => o.kind === 'mask' && o.domain === 'dns-txt-value')).toBe(true)

    const patches = resolveFrozenPacketPlan(frozen, {
      mapping: new SessionMapping(),
      fingerprints: new FingerprintSession('t01b-mask'),
      packetIndex: 0,
      packetNumber: 1,
    })
    expect(patches.some((p) => p.offset === 8 && p.data.length === 12)).toBe(true)
  })

  it('DNS unknown RDATA sanitize plans without legacyResolve when deferrals are journal-backed', () => {
    const buf = buildUnknownRdataAnswer([0xde, 0xad, 0xbe, 0xef])
    const collector = new PatchCollector(buf.length)
    const intents = new IntentCollector()
    expect(
      sanitizeDns(buf, 0, buf.length, collector, new SessionMapping(), intents, 0),
    ).toBe(true)
    expect(collector.isDeferredFullySymbolized()).toBe(true)
    expect(collector.getSymbolicMaskOps().some((o) => o.domain === 'dns-rdata:153')).toBe(true)

    const result = {
      packetIndex: 0,
      patches: collector.getPatches(),
      resolvePatches: (ctx: Parameters<PatchCollector['resolveDeferred']>[0]) => {
        collector.resolveDeferred(ctx)
        return collector.getPatches()
      },
      symbolicMapOps: collector.getSymbolicJournalOps(),
      deferredFullySymbolized: collector.isDeferredFullySymbolized(),
      coverage: [],
      drop: false,
      issues: [] as string[],
    }

    const frozen = freezeSanitizationResult({
      packetIndex: 0,
      packetNumber: 1,
      bufferLength: buf.length,
      result,
      intents: intents.intents,
    })
    expect(frozen.legacyResolve).toBeUndefined()
    const maskOp = frozen.ops.find((o) => o.kind === 'mask' && o.domain === 'dns-rdata:153')
    expect(maskOp).toBeDefined()

    const patches = resolveFrozenPacketPlan(frozen, {
      mapping: new SessionMapping(),
      fingerprints: new FingerprintSession('t01b-dns-txt'),
      packetIndex: 0,
      packetNumber: 1,
    })
    const masked = patches.find((p) => p.offset === maskOp!.offset)
    expect(masked).toBeDefined()
    const original = buf.slice(maskOp!.offset, maskOp!.offset + maskOp!.length)
    expect([...masked!.data]).not.toEqual([...original])
  })
})
