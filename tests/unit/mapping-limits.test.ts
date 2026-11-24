import { describe, expect, it, beforeEach, vi } from 'vitest'

vi.mock('../../src/domain/capabilityContract.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/domain/capabilityContract.ts')>()
  return { ...actual, MAX_ENTITY_CARDINALITY: 3 }
})

import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import { OccurrenceIndex } from '../../src/mapping/occurrenceIndex'
import { RESOLVE_ERROR } from '../../src/mapping/types'
import type { CanonicalIdentity } from '../../src/mapping/types'

function id(category: CanonicalIdentity['category'], canonical: string): CanonicalIdentity {
  return {
    category,
    canonical,
    constraint: { kind: 'ipv4-wire' },
    occurrence: { kind: 'text', sourceId: 's', line: 1, start: 0, end: 4 },
  }
}

describe('Stage 19 mapping limits', () => {
  let authority: MappingAuthority

  beforeEach(() => {
    authority = new MappingAuthority()
  })

  it('fails closed at identity limit + 1 without changing mappingRevision', () => {
    for (let i = 1; i <= 3; i++) {
      const ok = authority.resolve({
        generationId: `g${i}`,
        sourceId: 's',
        identities: [id('ipv4', `10.0.0.${i}`)],
      })
      expect(ok.ok).toBe(true)
    }
    expect(authority.getMappingRevision()).toBe(3)

    const overflow = authority.resolve({
      generationId: 'overflow',
      sourceId: 's',
      identities: [id('ipv4', '10.0.0.99')],
    })
    expect(overflow.ok).toBe(false)
    if (overflow.ok) return
    expect(overflow.code).toBe(RESOLVE_ERROR.cardinalityOverflow)
    expect(authority.getMappingRevision()).toBe(3)
  })

  it('occurrence index dedupes identical refs without double-counting bytes', () => {
    const idx = new OccurrenceIndex()
    const ref = { kind: 'text' as const, sourceId: 'a', line: 1, start: 0, end: 1 }
    expect(idx.append(1, ref)).toBe(true)
    const bytesAfterFirst = idx.getBytesUsed()
    expect(idx.append(1, ref)).toBe(true)
    expect(idx.getBytesUsed()).toBe(bytesAfterFirst)
    expect(idx.countForIdentity(1)).toBe(1)
  })
})
