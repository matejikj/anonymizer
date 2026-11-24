import { describe, expect, it, beforeEach } from 'vitest'
import { vi } from 'vitest'

vi.mock('../../src/domain/capabilityContract.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/domain/capabilityContract.ts')>()
  return {
    ...actual,
    MAPPING_CAPABILITY_LIMITS: {
      ...actual.MAPPING_CAPABILITY_LIMITS,
      maxOccurrenceIndexBytes: 24,
    },
  }
})

import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import { RESOLVE_ERROR } from '../../src/mapping/types'

describe('Stage 19 occurrence budget fail-closed', () => {
  let authority: MappingAuthority

  beforeEach(() => {
    authority = new MappingAuthority()
  })

  it('rejects resolve when occurrence index would exceed byte budget', () => {
    const result = authority.resolve({
      generationId: 'g1',
      sourceId: 's',
      identities: [{
        category: 'ip',
        canonical: '10.0.0.1',
        constraint: { kind: 'ipv4-wire' },
        occurrence: { kind: 'text', sourceId: 'very-long-source-name', line: 1, start: 0, end: 50 },
      }],
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe(RESOLVE_ERROR.occurrenceIndexOverflow)
    expect(authority.getMappingRevision()).toBe(0)
    expect(authority.getRegistry().size).toBe(0)
  })
})
