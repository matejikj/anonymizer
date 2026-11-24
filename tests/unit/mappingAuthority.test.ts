import { describe, expect, it, beforeEach } from 'vitest'
import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import { RESOLVE_ERROR } from '../../src/mapping/types'
import type { CanonicalIdentity } from '../../src/mapping/types'

function id(category: CanonicalIdentity['category'], canonical: string): CanonicalIdentity {
  return {
    category,
    canonical,
    constraint: category === 'ipv4'
      ? { kind: 'ipv4-wire' }
      : category === 'mac'
        ? { kind: 'mac-wire' }
        : { kind: 'hostname-ascii', labelCount: 1, maxLabelLength: canonical.length },
  }
}

describe('MappingAuthority', () => {
  let authority: MappingAuthority

  beforeEach(() => {
    authority = new MappingAuthority()
  })

  it('reuses alias for the same canonical identity in one session', () => {
    const req = {
      generationId: 'gen-1',
      sourceId: 'pcap-a',
      identities: [id('ipv4', '192.168.1.1'), id('ipv4', '192.168.1.1')],
    }
    const result = authority.resolve(req)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    // Session snapshot is registry-union keyed — duplicate batch identities collapse to one entry.
    expect(result.snapshot.scope).toBe('session')
    expect(result.snapshot.entries).toHaveLength(1)
    expect(result.snapshot.entries[0]!.canonical).toBe('192.168.1.1')
    expect(result.snapshot.entries[0]!.occurrenceCount).toBe(2)
    expect(result.snapshot.revision).toBe(1)
  })

  it('increments revision only on successful resolve', () => {
    const first = authority.resolve({
      generationId: 'g1',
      sourceId: 's',
      identities: [id('ipv4', '10.0.0.1')],
    })
    expect(first.ok).toBe(true)
    expect(authority.getRevision()).toBe(1)

    authority.requestCancel('g2')
    const cancelled = authority.resolve({
      generationId: 'g2',
      sourceId: 's',
      identities: [id('ipv4', '10.0.0.2')],
    })
    expect(cancelled.ok).toBe(false)
    expect(authority.getRevision()).toBe(1)

    const second = authority.resolve({
      generationId: 'g3',
      sourceId: 's',
      identities: [id('ipv4', '10.0.0.2')],
    })
    expect(second.ok).toBe(true)
    expect(authority.getRevision()).toBe(2)
  })

  it('does not publish snapshot on cancel', () => {
    authority.requestCancel('cancel-me')
    const result = authority.resolve({
      generationId: 'cancel-me',
      sourceId: 's',
      identities: [id('mac', 'aa:bb:cc:dd:ee:ff')],
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe(RESOLVE_ERROR.cancelled)
    expect(authority.getPublishedSnapshot()).toBeNull()
    expect(authority.getRevision()).toBe(0)
  })

  it('maps 1000 unique IPv4 addresses without collision', () => {
    const identities: CanonicalIdentity[] = []
    for (let i = 0; i < 1000; i++) {
      identities.push(id('ipv4', `172.16.${(i >> 8) & 0xff}.${i & 0xff}`))
    }
    const result = authority.resolve({ generationId: 'bulk', sourceId: 'pcap', identities })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const aliases = new Set(result.snapshot.entries.map((e) => e.alias))
    expect(aliases.size).toBe(1000)
  })
})
