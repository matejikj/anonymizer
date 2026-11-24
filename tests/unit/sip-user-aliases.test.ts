import { describe, expect, it } from 'vitest'
import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import type { CanonicalIdentity, MappingSnapshot } from '../../src/mapping/types'
import { aliasForSnapshotConstraintStrict } from '../../src/mapping/mappingRegistry'
import { SnapshotMappingAdapter } from '../../src/pcap/plan/snapshotMappingAdapter'

function user(original: string, category: 'sip-user' | 'user-id' = 'sip-user'): CanonicalIdentity {
  return {
    category,
    canonical: original.toLowerCase(),
    originalSpelling: original,
    constraint: { kind: 'text-ascii', byteLength: original.length },
    source: { detectorId: category === 'sip-user' ? 'pcap' : 'text' },
  }
}

function resolve(authority: MappingAuthority, identities: CanonicalIdentity[]): MappingSnapshot {
  const result = authority.resolve({ generationId: 'g', sourceId: 's', identities })
  expect(result.ok).toBe(true)
  if (!result.ok) throw new Error(result.code)
  return result.snapshot
}

describe('length-constrained shared SIP user aliases', () => {
  it('keeps 256 four-character users distinct in both the snapshot and rendered wire aliases', () => {
    const identities = Array.from({ length: 256 }, (_, n) => user(String(6000 + n)))
    const snapshot = resolve(new MappingAuthority(), identities)
    const adapter = new SnapshotMappingAdapter(snapshot)
    const aliases = identities.map(id => adapter.aliasFor(id.category, id.canonical, id.constraint, id.originalSpelling))
    expect(new Set(aliases).size).toBe(identities.length)
    for (const [i, alias] of aliases.entries()) {
      expect(alias).toHaveLength(4)
      expect(alias).not.toBe(identities[i]!.originalSpelling)
      expect(aliasForSnapshotConstraintStrict(snapshot.entries[i]!, identities[i]!.constraint)).toBe(alias)
    }
    expect(snapshot.overflow).toBe(false)
  })

  it.each([['user-id', 'sip-user'], ['sip-user', 'user-id']] as const)(
    'reuses the exact wire alias when %s is resolved before %s', (first, second) => {
      const authority = new MappingAuthority()
      const a = resolve(authority, [user('ALICE', first)])
      const b = resolve(authority, [user('alice', second)])
      expect(b.entries).toHaveLength(1)
      expect(a.entries[0]!.alias).toHaveLength(5)
      expect(b.entries[0]!.alias).toBe(a.entries[0]!.alias)
      const adapter = new SnapshotMappingAdapter(b)
      expect(adapter.aliasFor(first, 'alice', { kind: 'text-ascii', byteLength: 5 }, 'alice')).toBe(a.entries[0]!.alias)
    },
  )

  it('allocates different-length spellings of one user in the same batch without truncation', () => {
    const authority = new MappingAuthority()
    const a = user('ALICE')
    const b = user(' alice ')
    // Canonical user normalization trims whitespace; both spellings share one identity.
    const snapshot = resolve(authority, [a, b, user('bob')])
    expect(snapshot.entries).toHaveLength(2)
    const entry = snapshot.entries[0]!
    expect(aliasForSnapshotConstraintStrict(entry, a.constraint)).toHaveLength(5)
    expect(aliasForSnapshotConstraintStrict(entry, b.constraint)).toHaveLength(7)
    const again = resolve(authority, [a, b])
    expect(again.entries[0]!.aliases).toEqual(entry.aliases)
  })

  it('discards short-alias allocations on aborted staging', () => {
    const authority = new MappingAuthority()
    const staged = authority.resolveStaging({ generationId: 'g', sourceId: 's', identities: [user('6000')] })
    expect(staged.ok).toBe(true)
    if (!staged.ok) return
    const alias = staged.snapshot.entries[0]!.alias
    authority.abortStaging()
    const snapshot = resolve(authority, [user('6001'), user('6000')])
    expect(snapshot.entries[0]!.alias).toBe(alias)
    expect(snapshot.entries[1]!.alias).not.toBe(alias)
  })

  it('keeps explicit custom fixed user replacements', () => {
    const authority = new MappingAuthority()
    const result = authority.resolve({
      generationId: 'g', sourceId: 'text',
      identities: [{ ...user('alice', 'user-id'), source: { detectorId: 'custom.rule', ruleId: 'fixed-user' } }],
      customRules: [{ id: 'fixed-user', name: 'Fixed user', enabled: true, priority: 1000,
        kind: 'literal', pattern: 'alice', category: 'user-id', replacementMode: 'fixed', fixedReplacement: '[USER]' }],
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.snapshot.entries[0]!.alias).toBe('[USER]')
    expect(result.snapshot.entries[0]!.disposition).toBe('ambiguous-fixed')
  })

  it('marks the session overflow when one-character aliases are exhausted', () => {
    const authority = new MappingAuthority()
    const snapshot = resolve(authority, [...'abcdefghijklmnopqrstuvwxyz0123456789'].map(value => user(value)))
    expect(snapshot.overflow).toBe(false)
    expect(new Set(snapshot.entries.map(e => e.alias)).size).toBe(36)
    for (const entry of snapshot.entries) {
      expect(entry.alias).toHaveLength(1)
      expect(entry.alias).not.toBe(entry.canonical)
    }
    const exhausted = resolve(authority, [user('_')])
    expect(exhausted.overflow).toBe(true)
    expect(exhausted.entries.at(-1)!.alias).not.toBe('_')
  })
})
