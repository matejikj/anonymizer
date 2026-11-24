/**
 * T04 — IncidentLog bounds + PatchCollector field fallback (deterministic, no value leak).
 */

import { describe, expect, it } from 'vitest'
import {
  IncidentLog,
  DEFAULT_INCIDENT_LOG_CAPACITY,
  DEFAULT_INCIDENT_LOG_MAX_BYTES,
} from '../../../src/domain/anonymizationIncident'
import { MappingLookupError } from '../../../src/pcap/anonymization/mappingErrors'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { createFieldFallbackBytes } from '../../../src/pcap/sanitize/fieldFallback'
import type { MappingLike } from '../../../src/pcap/anonymization/mapping'

function throwingMapping(): MappingLike {
  return {
    overflow: false,
    map() {
      throw new MappingLookupError('missing-snapshot-alias', { category: 'hostname' })
    },
    get() {
      return undefined
    },
    aliasFor() {
      throw new MappingLookupError('missing-snapshot-alias', { category: 'hostname' })
    },
  }
}

describe('T04 IncidentLog', () => {
  it('bounds retained records and keeps aggregate counts', () => {
    const log = new IncidentLog(10)
    for (let i = 0; i < 10_000; i++) {
      log.record({
        unit: 'field',
        sourceId: 'src',
        packetIndex: i,
        protocol: i % 2 === 0 ? 'sip' : 'sdp',
        category: 'hostname',
        stage: 'plan',
        reason: 'mapping-alias-missing',
        fallback: 'field-masked',
      })
    }
    const snap = log.snapshot()
    expect(snap.incidents.length).toBe(10)
    expect(snap.truncated).toBe(true)
    expect(snap.totalFailures).toBe(10_000)
    const sipAgg = snap.aggregates.find(
      (a) => a.protocol === 'sip' && a.reason === 'mapping-alias-missing',
    )
    expect(sipAgg?.count).toBe(5_000)
    expect(DEFAULT_INCIDENT_LOG_CAPACITY).toBe(1_000)
    expect(DEFAULT_INCIDENT_LOG_MAX_BYTES).toBeGreaterThan(0)
  })

  it('enforces byte budget in addition to count capacity', () => {
    const log = new IncidentLog(10_000, 400)
    for (let i = 0; i < 50; i++) {
      log.record({
        unit: 'field',
        sourceId: 'src-with-a-moderately-long-id',
        packetIndex: i,
        protocol: 'sip',
        category: 'hostname',
        stage: 'plan',
        reason: 'mapping-alias-missing',
        fallback: 'field-masked',
      })
    }
    const snap = log.snapshot()
    expect(snap.truncated).toBe(true)
    expect(snap.incidents.length).toBeLessThan(50)
    expect(snap.incidents.length).toBeGreaterThan(0)
    expect(snap.totalFailures).toBe(50)
  })

  it('serialized incidents never contain canary identity values', () => {
    const canary = 'secret-user@example.internal'
    const log = new IncidentLog()
    log.record({
      unit: 'field',
      sourceId: 'src',
      packetIndex: 0,
      protocol: 'sip',
      category: 'hostname',
      stage: 'plan',
      reason: 'mapping-alias-missing',
      fallback: 'field-masked',
    })
    const json = JSON.stringify(log.snapshot())
    expect(json).not.toContain(canary)
    expect(json).not.toContain('example.internal')
  })
})

describe('T04 PatchCollector field fallback', () => {
  it('masks deferred field on MappingLookupError and records incident', () => {
    const collector = new PatchCollector(32)
    const original = new Uint8Array(8)
    for (let i = 0; i < 8; i++) original[i] = 0x41 + i // ABCDEFGH
    // Reserve deferred over a text span; compute throws.
    collector.addDeferred(
      4,
      8,
      () => {
        throw new MappingLookupError('missing-snapshot-alias', { category: 'hostname' })
      },
      { fallbackKind: 'text-x', protocol: 'sip', category: 'hostname', packetIndex: 3 },
    )

    const log = new IncidentLog()
    collector.resolveDeferred({
      mapping: throwingMapping(),
      fingerprints: new FingerprintSession(),
      incidentLog: log,
      sourceId: 'test.pcap',
      packetIndex: 3,
      packetNumber: 4,
    })

    const patches = collector.getPatches()
    expect(patches).toHaveLength(1)
    const fill = patches[0]!
    expect(fill.offset).toBe(4)
    expect(fill.data.length).toBe(8)
    expect([...fill.data].every((b) => b === 0x78)).toBe(true) // 'x'
    expect(fill.data.includes(0x00)).toBe(false)
    expect(Buffer.from(fill.data).equals(Buffer.from(original))).toBe(false)

    const snap = log.snapshot()
    expect(snap.totalFailures).toBe(1)
    expect(snap.incidents[0]).toMatchObject({
      unit: 'field',
      reason: 'mapping-alias-missing',
      fallback: 'field-masked',
      category: 'hostname',
      protocol: 'sip',
      packetIndex: 3,
      packetNumber: 4,
    })
    expect(JSON.stringify(snap)).not.toContain('ABCDEFGH')
  })

  it('digits fallback is deterministic for same (packetIndex, offset, length)', () => {
    const a = createFieldFallbackBytes({
      length: 6,
      kind: 'digits',
      packetIndex: 2,
      offset: 10,
    })
    const b = createFieldFallbackBytes({
      length: 6,
      kind: 'digits',
      packetIndex: 2,
      offset: 10,
    })
    expect([...a]).toEqual([...b])
    expect([...a].every((c) => c >= 0x30 && c <= 0x39)).toBe(true)
  })

  it('other deferred patches still resolve when one field fails', () => {
    const collector = new PatchCollector(16)
    collector.addDeferred(0, 4, () => new Uint8Array([1, 2, 3, 4]), {
      fallbackKind: 'binary-mask',
      category: 'ipv4',
    })
    collector.addDeferred(
      8,
      4,
      () => {
        throw new MappingLookupError('missing-snapshot-alias', { category: 'ipv4' })
      },
      { fallbackKind: 'binary-mask', category: 'ipv4', packetIndex: 0 },
    )
    const log = new IncidentLog()
    collector.resolveDeferred({
      mapping: throwingMapping(),
      fingerprints: new FingerprintSession(),
      incidentLog: log,
      sourceId: 's',
      packetIndex: 0,
      packetNumber: 1,
    })
    const patches = collector.getPatches()
    expect(patches).toHaveLength(2)
    expect([...patches[0]!.data]).toEqual([1, 2, 3, 4])
    expect(patches[1]!.data.length).toBe(4)
    expect(log.snapshot().totalFailures).toBe(1)
  })
})
