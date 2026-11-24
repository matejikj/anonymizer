import { describe, expect, it } from 'vitest'
import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import type { CanonicalIdentity } from '../../src/mapping/types'

const identity = (canonical: string): CanonicalIdentity => ({
  category: 'ip',
  canonical,
  constraint: { kind: 'ipv4-wire' },
  originalSpelling: canonical,
  source: { detectorId: 'test' },
})

describe('Stage 24 mapping resolve journal', () => {
  it('resolveStaging commits atomically and abort discards pending delta', () => {
    const authority = new MappingAuthority()

    const staged = authority.resolveStaging({
      generationId: 'g1',
      sourceId: 's1',
      identities: [identity('10.0.0.1')],
    })
    expect(staged.ok).toBe(true)
    if (!staged.ok) return
    expect(authority.getMappingRevision()).toBe(0)
    expect(authority.hasPendingStaging()).toBe(true)

    const committed = authority.commitStaging()
    expect(committed.ok).toBe(true)
    if (!committed.ok) return
    expect(authority.getMappingRevision()).toBe(1)
    expect(authority.hasPendingStaging()).toBe(false)

    const staged2 = authority.resolveStaging({
      generationId: 'g2',
      sourceId: 's2',
      identities: [identity('10.0.0.2')],
    })
    expect(staged2.ok).toBe(true)
    authority.abortStaging()
    expect(authority.getMappingRevision()).toBe(1)
    expect(authority.hasPendingStaging()).toBe(false)
  })

  it('reuses alias for compatible identity; sequential commits leave registry union intact', () => {
    const authority = new MappingAuthority()
    authority.resolve({
      generationId: 'g1',
      sourceId: 's1',
      identities: [identity('10.0.0.5')],
    })

    const staged = authority.resolveStaging({
      generationId: 'g2',
      sourceId: 's2',
      identities: [identity('10.0.0.5'), identity('10.0.0.9')],
    })
    expect(staged.ok).toBe(true)
    if (!staged.ok) return

    const preview = staged.snapshot.entries.find((e) => e.canonical === '10.0.0.5')
    const first = authority.getPublishedSnapshot()?.entries.find((e) => e.canonical === '10.0.0.5')
    expect(preview?.alias).toBe(first?.alias)

    const committed = authority.commitStaging()
    expect(committed.ok).toBe(true)

    // Production sequence: second source with only a new identity (no manual aggregate publish).
    const stagedOnlyNew = authority.resolveStaging({
      generationId: 'g3',
      sourceId: 's3',
      identities: [identity('10.0.0.2')],
    })
    expect(stagedOnlyNew.ok).toBe(true)
    const committedNew = authority.commitStaging()
    expect(committedNew.ok).toBe(true)

    // Registry always holds the union (sanity for Stage 0 vs Stage 1).
    const registryCanonicals = authority
      .getRegistry()
      .entries()
      .map((e) => e.canonical)
      .sort()
    expect(registryCanonicals).toEqual(['10.0.0.2', '10.0.0.5', '10.0.0.9'])
  })
})
