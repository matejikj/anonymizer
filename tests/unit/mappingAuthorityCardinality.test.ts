import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'

vi.mock('../../src/domain/capabilityContract.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/domain/capabilityContract.ts')>()
  return { ...actual, MAX_ENTITY_CARDINALITY: 5 }
})

import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import { RESOLVE_ERROR } from '../../src/mapping/types'
import type { CanonicalIdentity } from '../../src/mapping/types'

function id(category: CanonicalIdentity['category'], canonical: string): CanonicalIdentity {
  return { category, canonical, constraint: { kind: 'ipv4-wire' } }
}

describe('MappingAuthority cardinality boundary', () => {
  let authority: MappingAuthority

  beforeEach(() => {
    authority = new MappingAuthority()
  })

  it('fails closed at limit + 1 without changing revision', () => {
    const fill = authority.resolve({
      generationId: 'fill',
      sourceId: 's',
      identities: [
        id('ipv4', '10.0.0.1'),
        id('ipv4', '10.0.0.2'),
        id('ipv4', '10.0.0.3'),
        id('ipv4', '10.0.0.4'),
        id('ipv4', '10.0.0.5'),
      ],
    })
    expect(fill.ok).toBe(true)
    expect(authority.getRevision()).toBe(1)

    const overflow = authority.resolve({
      generationId: 'overflow',
      sourceId: 's',
      identities: [id('ipv4', '10.0.0.6')],
    })
    expect(overflow.ok).toBe(false)
    if (overflow.ok) return
    expect(overflow.code).toBe(RESOLVE_ERROR.cardinalityOverflow)
    expect(authority.getRevision()).toBe(1)
  })
})
