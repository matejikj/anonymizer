import { describe, expect, it, beforeEach } from 'vitest'
import {
  assertShareableManifestHasNoLeaks,
  buildShareableCorrelationGroups,
  needsShareableCorrelationManifest,
  resetShareableManifestCounterForTests,
} from '../../src/correlation/export/correlationShareManifest'
import type { MappingSnapshot, MappingSnapshotEntry, RepresentationAlias } from '../../src/mapping/types'

function alias(value: string): RepresentationAlias {
  return {
    alias: value,
    constraint: { kind: 'ipv4-wire' },
    disposition: 'bijective',
  }
}

function entry(partial: Partial<MappingSnapshotEntry> & Pick<MappingSnapshotEntry, 'identityId' | 'canonical' | 'alias'>): MappingSnapshotEntry {
  return {
    category: 'ip',
    aliases: [alias(partial.alias)],
    constraint: { kind: 'ipv4-wire' },
    disposition: 'bijective',
    occurrenceCount: 1,
    ...partial,
  }
}

function snapshot(entries: MappingSnapshotEntry[]): MappingSnapshot {
  return {
    scope: 'session',
    revision: 1,
    mappingRevision: 1,
    canonicalizationVersion: 1,
    generationId: 'g1',
    sourceId: 'multi',
    overflow: false,
    entries,
  }
}

describe('Stage 29 shareable correlation manifest', () => {
  beforeEach(() => {
    resetShareableManifestCounterForTests()
  })

  it('returns null manifest groups when every identity has a single alias', () => {
    const snap = snapshot([entry({ identityId: 1, canonical: '10.0.0.1', alias: '192.0.2.1' })])
    expect(needsShareableCorrelationManifest(snap)).toBe(false)
    expect(buildShareableCorrelationGroups(snap)).toEqual([])
  })

  it('creates correlation groups for multi-alias identities', () => {
    const snap = snapshot([
      {
        ...entry({ identityId: 1, canonical: '10.0.0.1', alias: '192.0.2.1' }),
        aliases: [alias('192.0.2.1'), alias('192.0.2.99')],
      },
    ])
    expect(needsShareableCorrelationManifest(snap)).toBe(true)
    const groups = buildShareableCorrelationGroups(snap)
    expect(groups).toHaveLength(1)
    expect(groups[0]!.aliases).toEqual(['192.0.2.1', '192.0.2.99'])
    expect(groups[0]!.tag).toMatch(/^c/)
  })

  it('passes must-not-leak test — no canonical, fingerprint, or original IP', () => {
    const snap = snapshot([
      {
        ...entry({ identityId: 1, canonical: '10.0.0.5', alias: '192.0.2.10' }),
        aliases: [alias('192.0.2.10'), alias('192.0.2.11')],
      },
    ])
    const groups = buildShareableCorrelationGroups(snap)
    const manifest = {
      format: 'rnd-log-anonymizer-correlation-manifest' as const,
      schemaVersion: 1 as const,
      partial: false,
      sources: [
        { sourceId: 'a', outputFileName: 'a.anonym.log', kind: 'text' as const },
        { sourceId: 'b', outputFileName: 'b.anonym.log', kind: 'text' as const },
      ],
      correlationGroups: groups,
    }
    const json = JSON.stringify(manifest)
    assertShareableManifestHasNoLeaks(json, ['10.0.0.5'])
    expect(json).not.toContain('10.0.0.5')
    expect(json).not.toContain('fingerprint')
    expect(json).not.toContain('passphrase')
    expect(json).not.toContain('identityId')
  })

  it('allows original substrings that only appear in outputFileName', () => {
    const manifest = {
      format: 'rnd-log-anonymizer-correlation-manifest' as const,
      schemaVersion: 1 as const,
      partial: false,
      sources: [
        {
          sourceId: 'a',
          outputFileName: 'template-appsrv.anonym.log',
          kind: 'text' as const,
        },
      ],
      correlationGroups: [
        { tag: 'c1-deadbeef', category: 'host' as const, aliases: ['h-aa11', 'h-bb22'] },
      ],
    }
    const json = JSON.stringify(manifest)
    expect(() => assertShareableManifestHasNoLeaks(json, ['appsrv'])).not.toThrow()
  })

  it('still rejects originals embedded in correlation aliases', () => {
    const manifest = {
      format: 'rnd-log-anonymizer-correlation-manifest' as const,
      schemaVersion: 1 as const,
      partial: false,
      sources: [{ sourceId: 'a', outputFileName: 'out.anonym.log', kind: 'text' as const }],
      correlationGroups: [
        { tag: 'c1-deadbeef', category: 'host' as const, aliases: ['safe', 'secrethost-leak'] },
      ],
    }
    const json = JSON.stringify(manifest)
    expect(() => assertShareableManifestHasNoLeaks(json, ['secrethost'])).toThrow(/original identifier/)
  })
})
