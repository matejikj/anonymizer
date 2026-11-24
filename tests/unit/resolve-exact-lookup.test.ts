import { describe, expect, it } from 'vitest'
import type { MappingBundlePayload } from '../../src/mapping/bundle/types'
import { exactLookupByAlias, loadAliasIndexFromPayload } from '../../src/mapping/resolve'

function ambiguousRedactedPayload(): MappingBundlePayload {
  return {
    sessionId: 'test-session',
    canonicalizationVersion: 1,
    mappingRevision: 1,
    sources: [{ id: 'log-a', kind: 'text', name: 'test.log' }],
    entries: [
      {
        identityId: 1,
        category: 'custom',
        canonical: 'alpha-secret',
        alias: '[REDACTED]',
        disposition: 'ambiguous-fixed',
        occurrenceCount: 2,
      },
      {
        identityId: 2,
        category: 'custom',
        canonical: 'beta-secret',
        alias: '[REDACTED]',
        disposition: 'ambiguous-fixed',
        occurrenceCount: 1,
      },
    ],
  }
}

describe('Stage 22 exact lookup', () => {
  it('fixed [REDACTED] with two originals returns two candidates', () => {
    const payload = ambiguousRedactedPayload()
    const result = exactLookupByAlias('[REDACTED]', 'imported-bundle', payload)
    expect('code' in result).toBe(false)
    if ('code' in result) return

    expect(result.ambiguous).toBe(true)
    expect(result.candidates).toHaveLength(2)
    const canonicals = result.candidates.map((c) => c.canonical).sort()
    expect(canonicals).toEqual(['alpha-secret', 'beta-secret'])
    expect(result.candidates.every((c) => c.disposition === 'ambiguous-fixed')).toBe(true)
  })

  it('lookupExact is O(1) via alias index map', () => {
    const payload = ambiguousRedactedPayload()
    const index = loadAliasIndexFromPayload(payload)
    expect('code' in index).toBe(false)
    if ('code' in index) return

    const first = index.lookupExact('[REDACTED]')
    const second = index.lookupExact('[REDACTED]')
    expect(first).toBe(second)
    expect(first).toHaveLength(2)
  })

  it('rejects empty alias', () => {
    const result = exactLookupByAlias('   ', 'imported-bundle', ambiguousRedactedPayload())
    expect('code' in result).toBe(true)
    if (!('code' in result)) return
    expect(result.code).toBe('resolve-alias-empty')
  })
})
