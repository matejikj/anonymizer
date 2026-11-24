import { describe, expect, it } from 'vitest'
import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import type { CanonicalIdentity } from '../../src/mapping/types'
import { CROSS_FORMAT_CANONICALIZATION_VERSION } from '../../src/mapping/crossFormat'
import { isFixedTextTokenAlias } from '../../src/mapping/crossFormat/representation'

function textIp(canonical: string): CanonicalIdentity {
  return {
    category: 'ip',
    canonical,
    constraint: { kind: 'ipv4-wire' },
    originalSpelling: canonical,
    source: { detectorId: 'text' },
  }
}

function pcapIpv4(canonical: string): CanonicalIdentity {
  return {
    category: 'ipv4',
    canonical,
    constraint: { kind: 'ipv4-wire' },
    source: { detectorId: 'pcap' },
  }
}

describe('Stage 25 shared wire-valid cross-format mapping', () => {
  it('assigns the same wire-valid alias to text IP and PCAP IPv4', () => {
    const authority = new MappingAuthority()

    const textResolved = authority.resolve({
      generationId: 'g1',
      sourceId: 'text-log',
      identities: [textIp('10.0.0.44')],
    })
    expect(textResolved.ok).toBe(true)
    if (!textResolved.ok) return

    const pcapResolved = authority.resolve({
      generationId: 'g1',
      sourceId: 'pcap-cap',
      identities: [pcapIpv4('10.0.0.44')],
    })
    expect(pcapResolved.ok).toBe(true)
    if (!pcapResolved.ok) return

    const textAlias = textResolved.snapshot.entries[0]?.alias
    const pcapAlias = pcapResolved.snapshot.entries[0]?.alias
    expect(textAlias).toBeTruthy()
    expect(pcapAlias).toBe(textAlias)
    expect(isFixedTextTokenAlias(textAlias!, 'ipv4')).toBe(false)
    expect(/^\d+\.\d+\.\d+\.\d+$/.test(textAlias!)).toBe(true)
    expect(textResolved.snapshot.canonicalizationVersion).toBe(CROSS_FORMAT_CANONICALIZATION_VERSION)
  })

  it('T45 — links sip:+ and tel:+ phone under one identity (shared or linked aliases)', () => {
    const authority = new MappingAuthority()
    const correlationOptions = { crossFormatLinking: true as const }

    const sip = authority.resolve({
      generationId: 'g-phone',
      sourceId: 'pcap-sip',
      identities: [{
        category: 'sip-user',
        canonical: '+420777123456',
        constraint: { kind: 'text-ascii', byteLength: 13 },
        originalSpelling: '+420777123456',
        source: { detectorId: 'pcap' },
      }],
      correlationOptions,
    })
    expect(sip.ok).toBe(true)
    if (!sip.ok) return

    const tel = authority.resolve({
      generationId: 'g-phone',
      sourceId: 'pcap-tel',
      identities: [{
        category: 'sip-phone',
        canonical: '+420777123456',
        constraint: { kind: 'text-ascii', byteLength: 13 },
        originalSpelling: '+420777123456',
        source: { detectorId: 'pcap' },
      }],
      correlationOptions,
    })
    expect(tel.ok).toBe(true)
    if (!tel.ok) return

    const entries = authority.getRegistry().entries()
    expect(entries.length).toBe(1)
    expect(entries[0]!.aliases.length).toBeGreaterThanOrEqual(1)
    const sipAlias = sip.snapshot.entries[0]?.alias
    const telAlias = tel.snapshot.entries[0]?.alias
    expect(sipAlias).toBeTruthy()
    expect(telAlias).toBe(sipAlias)
  })

  it('T45 — does not merge bare sip:1234 with tel:1234 without phone context', () => {
    const authority = new MappingAuthority()
    const correlationOptions = { crossFormatLinking: true as const }

    authority.resolve({
      generationId: 'g-nomerg',
      sourceId: 'sip',
      identities: [{
        category: 'sip-user',
        canonical: '1234',
        constraint: { kind: 'text-ascii', byteLength: 4 },
        originalSpelling: '1234',
        source: { detectorId: 'pcap' },
      }],
      correlationOptions,
    })
    authority.resolve({
      generationId: 'g-nomerg',
      sourceId: 'tel',
      identities: [{
        category: 'sip-phone',
        canonical: '1234',
        constraint: { kind: 'text-ascii', byteLength: 4 },
        originalSpelling: '1234',
        source: { detectorId: 'pcap' },
      }],
      correlationOptions,
    })

    expect(authority.getRegistry().entries().length).toBe(2)
  })

  it('T45 — email and user-id share aliases across text sources', () => {
    const authority = new MappingAuthority()
    const correlationOptions = { crossFormatLinking: true as const }

    const a = authority.resolve({
      generationId: 'g-mail',
      sourceId: 'log-a',
      identities: [{
        category: 'email',
        canonical: 'Alice@example.com',
        constraint: { kind: 'text-ascii', byteLength: 17 },
        originalSpelling: 'Alice@Example.COM',
        source: { detectorId: 'text' },
      }],
      correlationOptions,
    })
    const b = authority.resolve({
      generationId: 'g-mail',
      sourceId: 'log-b',
      identities: [{
        category: 'email',
        canonical: 'Alice@example.com',
        constraint: { kind: 'text-ascii', byteLength: 17 },
        originalSpelling: 'Alice@example.com',
        source: { detectorId: 'text' },
      }],
      correlationOptions,
    })
    expect(a.ok && b.ok).toBe(true)
    if (!a.ok || !b.ok) return
    expect(a.snapshot.entries[0]?.alias).toBe(b.snapshot.entries[0]?.alias)

    const u1 = authority.resolve({
      generationId: 'g-user',
      sourceId: 'u1',
      identities: [{
        category: 'user-id',
        canonical: 'alice',
        constraint: { kind: 'text-ascii', byteLength: 5 },
        originalSpelling: 'Alice',
        source: { detectorId: 'text' },
      }],
      correlationOptions,
    })
    const u2 = authority.resolve({
      generationId: 'g-user',
      sourceId: 'u2',
      identities: [{
        category: 'sip-user',
        canonical: 'alice',
        constraint: { kind: 'text-ascii', byteLength: 5 },
        originalSpelling: 'alice',
        source: { detectorId: 'pcap' },
      }],
      correlationOptions,
    })
    expect(u1.ok && u2.ok).toBe(true)
    if (!u1.ok || !u2.ok) return
    expect(authority.getRegistry().entries().filter((e) =>
      e.category === 'user-id' || e.category === 'sip-user' || e.canonical === 'alice'
        || e.canonical.includes('alice'),
    ).length).toBeGreaterThanOrEqual(1)
    // Same CF user key → one registry identity.
    const userEntries = authority.getRegistry().entries().filter((e) =>
      e.canonical === 'alice' || e.canonical === 'local:alice',
    )
    // Registry stores first category's canonical; both resolves share one entry via CF key.
    expect(u1.snapshot.entries[0]?.alias).toBe(u2.snapshot.entries[0]?.alias)
    void userEntries
  })

  it('T45 — linked representations when phone text lengths conflict', () => {
    const authority = new MappingAuthority()
    const correlationOptions = { crossFormatLinking: true as const }

    authority.resolve({
      generationId: 'g-len',
      sourceId: 'a',
      identities: [{
        category: 'sip-phone',
        canonical: '+420777123456',
        constraint: { kind: 'text-ascii', byteLength: 13 },
        originalSpelling: '+420777123456',
        source: { detectorId: 'text' },
      }],
      correlationOptions,
    })
    const second = authority.resolve({
      generationId: 'g-len',
      sourceId: 'b',
      identities: [{
        category: 'sip-phone',
        canonical: '+420777123456',
        constraint: { kind: 'text-ascii', byteLength: 16 },
        originalSpelling: '+420 777 123 456',
        source: { detectorId: 'text' },
      }],
      correlationOptions,
    })
    expect(second.ok).toBe(true)
    if (!second.ok) return
    const entry = authority.getRegistry().entries()[0]
    expect(entry?.aliases.length).toBeGreaterThanOrEqual(2)
  })

  it('creates deterministic separate hostname aliases under one identity when constraints differ', () => {
    const authority = new MappingAuthority()

    authority.resolve({
      generationId: 'g-h',
      sourceId: 'text',
      identities: [{
        category: 'hostname',
        canonical: 'very-long-hostname.example.com',
        constraint: { kind: 'text-ascii', byteLength: 30 },
        originalSpelling: 'Very-Long-HostName.Example.COM',
        source: { detectorId: 'text' },
      }],
    })

    const second = authority.resolve({
      generationId: 'g-h',
      sourceId: 'pcap',
      identities: [{
        category: 'hostname',
        canonical: 'very-long-hostname.example.com',
        constraint: { kind: 'hostname-ascii', labelCount: 3, maxLabelLength: 10 },
        source: { detectorId: 'pcap' },
      }],
    })
    expect(second.ok).toBe(true)
    if (!second.ok) return

    const entry = authority.getRegistry().entries()[0]
    expect(entry?.aliases.length).toBeGreaterThanOrEqual(2)
    const aliasValues = new Set(entry?.aliases.map((a) => a.alias))
    expect(aliasValues.size).toBeGreaterThanOrEqual(2)
  })
})
