import { describe, expect, it } from 'vitest'
import {
  MAPPING_PROTOCOL_VERSION,
  MAPPING_WORKER_ERROR,
  validateProtocolVersion,
  validateResolveIdentities,
  snapshotToWire,
  snapshotFromWire,
} from '../../src/mapping/protocol'
import type { MappingSnapshot } from '../../src/mapping/types'

describe('mapping protocol validation', () => {
  it('rejects unsupported protocol version', () => {
    const err = validateProtocolVersion(99)
    expect(err?.code).toBe(MAPPING_WORKER_ERROR.invalidVersion)
  })

  it('accepts current protocol version', () => {
    expect(validateProtocolVersion(MAPPING_PROTOCOL_VERSION)).toBeNull()
  })

  it('rejects oversize identity batch before allocation', () => {
    const identities = Array.from({ length: 500_001 }, (_, i) => ({
      category: 'ipv4' as const,
      canonical: `10.0.${(i >> 8) & 0xff}.${i & 0xff}`,
      constraint: { kind: 'ipv4-wire' as const },
    }))
    const result = validateResolveIdentities(identities)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.error.code).toBe(MAPPING_WORKER_ERROR.oversizeBatch)
  })

  it('rejects invalid canonical values', () => {
    const result = validateResolveIdentities([
      { category: 'ipv4', canonical: 'not-an-ip', constraint: { kind: 'ipv4-wire' } },
    ])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.error.code).toBe(MAPPING_WORKER_ERROR.invalidIdentity)
  })

  it('round-trips snapshot through wire format', () => {
    const snapshot: MappingSnapshot = {
      scope: 'session',
      revision: 3,
      mappingRevision: 3,
      canonicalizationVersion: 1,
      generationId: 'gen-abc',
      sourceId: 'pcap-1',
      overflow: false,
      entries: [{
        identityId: 1,
        category: 'ipv4',
        canonical: '192.168.0.1',
        alias: '10.254.1.2',
        aliases: [{
          alias: '10.254.1.2',
          constraint: { kind: 'ipv4-wire' },
          disposition: 'bijective' as const,
        }],
        constraint: { kind: 'ipv4-wire' },
        disposition: 'bijective' as const,
        occurrenceCount: 1,
      }],
    }
    const round = snapshotFromWire(snapshotToWire(snapshot))
    expect(round).toEqual(snapshot)
  })
})
