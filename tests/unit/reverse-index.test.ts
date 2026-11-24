import { describe, expect, it, beforeEach } from 'vitest'
import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import { defaultTextWireConstraint } from '../../src/mapping/textCanonical'
import type { CanonicalIdentity } from '../../src/mapping/types'

function textId(
  category: CanonicalIdentity['category'],
  canonical: string,
  original?: string,
  ruleId?: string,
): CanonicalIdentity {
  return {
    category,
    canonical,
    constraint: defaultTextWireConstraint(category as 'ip', canonical, original ?? canonical),
    originalSpelling: original ?? canonical,
    source: { detectorId: 'test', ruleId },
    occurrence: {
      kind: 'text',
      sourceId: 'log-a',
      line: 1,
      start: 0,
      end: (original ?? canonical).length,
    },
  }
}

const FIXED_RULES = [{
  id: 'fix-all',
  name: 'fix',
  kind: 'literal' as const,
  pattern: 'x',
  category: 'custom' as const,
  enabled: true,
  priority: 1000,
  replacementMode: 'fixed' as const,
  fixedReplacement: '[REDACTED]',
}]

describe('Stage 19 reverse index', () => {
  let authority: MappingAuthority

  beforeEach(() => {
    authority = new MappingAuthority()
  })

  it('lookup by original returns alias for bijective text identity', () => {
    const resolved = authority.resolve({
      generationId: 'g1',
      sourceId: 'text',
      identities: [textId('ip', '10.0.0.1')],
    })
    expect(resolved.ok).toBe(true)
    if (!resolved.ok) return

    const lookup = authority.lookupByOriginal({ category: 'ip', canonical: '10.0.0.1' })
    expect(lookup.ok).toBe(true)
    if (!lookup.ok) return
    expect(lookup.candidates).toHaveLength(1)
    expect(lookup.candidates[0]!.alias).toBe(resolved.snapshot.entries[0]!.alias)
  })

  it('lookup by alias returns all candidates for ambiguous-fixed replacement', () => {
    authority.resolve({
      generationId: 'g1',
      sourceId: 'text',
      identities: [
        { ...textId('custom', 'alpha', 'alpha', 'fix-all'), canonical: 'alpha' },
        { ...textId('custom', 'beta', 'beta', 'fix-all'), canonical: 'beta' },
      ],
      customRules: FIXED_RULES,
    })

    const byAlias = authority.lookupByAlias({ alias: '[REDACTED]' })
    expect(byAlias.ok).toBe(true)
    if (!byAlias.ok) return
    expect(byAlias.candidates.length).toBe(2)
    expect(byAlias.candidates.every((c) => c.disposition === 'ambiguous-fixed')).toBe(true)
  })

  it('scrubs plaintext from reverse index when last occurrence is released', () => {
    const id = textId('email', 'user@corp.local', 'user@corp.local')
    const first = authority.resolve({ generationId: 'g1', sourceId: 'text', identities: [id] })
    expect(first.ok).toBe(true)
    if (!first.ok) return
    const alias1 = first.snapshot.entries[0]!.alias

    const released = authority.releaseOccurrence({
      category: 'email',
      canonical: 'user@corp.local',
      occurrence: id.occurrence!,
    })
    expect(released.ok).toBe(true)
    if (!released.ok) return
    expect(released.scrubbed).toBe(true)

    const lookup = authority.lookupByOriginal({ category: 'email', canonical: 'user@corp.local' })
    expect(lookup.ok).toBe(true)
    if (!lookup.ok) return
    expect(lookup.candidates).toHaveLength(0)

    const restored = authority.resolve({ generationId: 'g2', sourceId: 'text', identities: [id] })
    expect(restored.ok).toBe(true)
    if (!restored.ok) return
    expect(restored.snapshot.entries[0]!.alias).toBe(alias1)
  })

  it('mappingRevision increments monotonically', () => {
    const a = authority.resolve({ generationId: 'g1', sourceId: 's', identities: [textId('ip', '10.0.0.1')] })
    const b = authority.resolve({ generationId: 'g2', sourceId: 's', identities: [textId('ip', '10.0.0.2')] })
    expect(a.ok && b.ok).toBe(true)
    if (!a.ok || !b.ok) return
    expect(a.snapshot.mappingRevision).toBe(1)
    expect(b.snapshot.mappingRevision).toBe(2)
  })
})
