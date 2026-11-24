import { describe, expect, it, beforeEach } from 'vitest'
import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import { MappingRegistry } from '../../src/mapping/mappingRegistry'
import type { CanonicalIdentity } from '../../src/mapping/types'
import { defaultTextWireConstraint } from '../../src/mapping/textCanonical'

function textId(category: CanonicalIdentity['category'], canonical: string, original?: string): CanonicalIdentity {
  return {
    category,
    canonical,
    constraint: defaultTextWireConstraint(category as 'ip', canonical, original ?? canonical),
    originalSpelling: original ?? canonical,
    source: { detectorId: 'test.detector' },
  }
}

describe('Stage 18 identity model', () => {
  let authority: MappingAuthority

  beforeEach(() => {
    authority = new MappingAuthority()
  })

  it('MappingRegistry is append-only and assigns stable identity IDs', () => {
    const registry = new MappingRegistry()
    const a = registry.register({
      category: 'ip',
      canonical: '10.0.0.1',
      alias: '10.255.90.1',
      constraint: { kind: 'ipv4-wire' },
      disposition: 'bijective',
      source: { detectorId: 'builtin.ip' },
    })
    const b = registry.register({
      category: 'ip',
      canonical: '10.0.0.1',
      alias: '10.255.90.1',
      constraint: { kind: 'ipv4-wire' },
      disposition: 'bijective',
      source: { detectorId: 'builtin.ip' },
    })
    expect(a.identityId).toBe(b.identityId)
    expect(registry.size).toBe(1)
  })

  it('text and PCAP identities resolve through one MappingAuthority', () => {
    const result = authority.resolve({
      generationId: 'g1',
      sourceId: 'mixed',
      identities: [
        textId('ip', '192.168.1.1'),
        {
          category: 'ipv4',
          canonical: '192.168.1.2',
          constraint: { kind: 'ipv4-wire' },
          source: { detectorId: 'pcap' },
        },
      ],
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.snapshot.entries).toHaveLength(2)
    expect(result.snapshot.entries[0]!.disposition).toBe('bijective')
    expect(result.snapshot.entries[0]!.aliases.length).toBeGreaterThan(0)
  })

  it('hostname spelling variants share correlation identity ID', () => {
    const first = authority.resolve({
      generationId: 'g1',
      sourceId: 'text',
      identities: [textId('hostname', 'server.example.com', 'Server.Example.COM.')],
    })
    expect(first.ok).toBe(true)
    if (!first.ok) return
    const id1 = first.snapshot.entries[0]!.identityId

    const second = authority.resolve({
      generationId: 'g2',
      sourceId: 'text',
      identities: [textId('hostname', 'server.example.com', 'server.example.com.')],
    })
    expect(second.ok).toBe(true)
    if (!second.ok) return
    expect(second.snapshot.entries[0]!.identityId).toBe(id1)
    expect(second.snapshot.entries[0]!.alias).toBe(first.snapshot.entries[0]!.alias)
  })

  it('snapshot entries carry occurrence counts from occurrence index', () => {
    const result = authority.resolve({
      generationId: 'g1',
      sourceId: 'text',
      identities: [
        {
          ...textId('email', 'a@b.c', 'a@b.c'),
          occurrence: { kind: 'text', sourceId: 'text', line: 1, start: 0, end: 5 },
        },
        {
          ...textId('email', 'a@b.c', 'a@b.c'),
          occurrence: { kind: 'text', sourceId: 'text', line: 2, start: 10, end: 15 },
        },
      ],
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.snapshot.entries.at(-1)!.occurrenceCount).toBeGreaterThanOrEqual(2)
  })
})
