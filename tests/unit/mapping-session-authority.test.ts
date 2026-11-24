/**
 * Stage 1 — MappingAuthority session snapshot, multi-constraint aliases, releaseOccurrence.
 */

import { describe, expect, it } from 'vitest'
import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import { primaryAlias, aliasForConstraint, aliasForSnapshotConstraintStrict } from '../../src/mapping/mappingRegistry'
import type { CanonicalIdentity } from '../../src/mapping/types'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import {
  assertShareableManifestHasNoLeaks,
  buildShareableCorrelationGroups,
} from '../../src/correlation/export/correlationShareManifest'

function ipWire(canonical: string): CanonicalIdentity {
  return {
    category: 'ip',
    canonical,
    constraint: { kind: 'ipv4-wire' },
    originalSpelling: canonical,
    source: { detectorId: 's1-test' },
  }
}

function ipText(canonical: string): CanonicalIdentity {
  return {
    category: 'ip',
    canonical,
    constraint: { kind: 'text-ascii', byteLength: canonical.length },
    originalSpelling: canonical,
    source: { detectorId: 's1-test' },
  }
}

describe('Stage 1 — MappingAuthority full-session snapshot', () => {
  it('keeps union of identities after 2–8 sequential commits', () => {
    const authority = new MappingAuthority()
    const expected: string[] = []
    for (let i = 1; i <= 8; i++) {
      const ip = `10.0.0.${i}`
      expected.push(ip)
      expect(
        authority.resolveStaging({
          generationId: 'g-s1',
          sourceId: `s${i}`,
          identities: [ipWire(ip)],
        }).ok,
      ).toBe(true)
      const committed = authority.commitStaging()
      expect(committed.ok).toBe(true)
      if (!committed.ok) return
      expect(committed.snapshot.scope).toBe('session')
      expect(committed.snapshot.entries.map((e) => e.canonical).sort()).toEqual([...expected].sort())
      expect(authority.getPublishedSnapshot()?.entries.map((e) => e.canonical).sort()).toEqual(
        [...expected].sort(),
      )
    }
  })

  it('stores distinct text/wire aliases for the same identity under cross-format linking', () => {
    const opts = { crossFormatLinking: true as const }
    const authority = new MappingAuthority()
    expect(
      authority.resolve({
        generationId: 'g1',
        sourceId: 'text',
        identities: [ipText('10.1.2.3')],
        correlationOptions: opts,
      }).ok,
    ).toBe(true)
    expect(
      authority.resolve({
        generationId: 'g1',
        sourceId: 'pcap',
        identities: [ipWire('10.1.2.3')],
        correlationOptions: opts,
      }).ok,
    ).toBe(true)

    const entry = authority.getPublishedSnapshot()?.entries.find((e) => e.canonical === '10.1.2.3')
    expect(entry).toBeTruthy()
    const distinct = new Set(entry!.aliases.map((a) => a.alias))
    expect(distinct.size).toBeGreaterThanOrEqual(2)
    const reg = authority.getRegistry().entries().find((e) => e.canonical === '10.1.2.3')!
    const textAlias = aliasForConstraint(reg, { kind: 'text-ascii', byteLength: '10.1.2.3'.length })
    const wireAlias = aliasForConstraint(reg, { kind: 'ipv4-wire' })
    expect(textAlias).not.toBe(wireAlias)
    expect(primaryAlias(reg)).toBe(entry!.alias)
  })

  it('scrubs plaintext on last occurrence release but keeps append-only alias in session snapshot', () => {
    const authority = new MappingAuthority()
    const occurrence = {
      kind: 'text' as const,
      sourceId: 'a',
      line: 0,
      start: 0,
      end: 8,
    }
    const resolved = authority.resolve({
      generationId: 'g1',
      sourceId: 'a',
      identities: [{ ...ipText('10.9.9.9'), occurrence }],
    })
    expect(resolved.ok).toBe(true)
    if (!resolved.ok) return
    const aliasBefore = resolved.snapshot.entries[0]!.alias

    const released = authority.releaseOccurrence({
      category: 'ip',
      canonical: '10.9.9.9',
      occurrence,
    })
    expect(released.ok).toBe(true)
    if (!released.ok) return
    expect(released.scrubbed).toBe(true)

    const session = authority.getPublishedSnapshot()
    expect(session).not.toBeNull()
    const entry = session!.entries.find((e) => e.canonical === '10.9.9.9')
    expect(entry?.alias).toBe(aliasBefore)
    expect(entry?.aliases.some((a) => a.alias === aliasBefore)).toBe(true)
    expect(
      authority.getRegistry().entries().find((e) => e.canonical === '10.9.9.9')?.plaintextActive,
    ).toBe(false)
  })
})

describe('Stage 1 — staging preview stays accurate across correlation sources', () => {
  it('resolveStaging preview includes a new constraint alias for an identity already committed by an earlier source', () => {
    // Mirrors the real correlation sequence that produced "missing-constraint-alias" in
    // production: a log source commits an IP under ipv4-wire first (e.g. dt.log's plain-text
    // IP detector), then a later pcap source stages the *same* canonical under a different
    // constraint (e.g. the same IP spelled out inside a SIP header, text-ascii) before its
    // own transaction commits. The preview snapshot resolveStaging returns is what
    // validateMappingClosure checks against — if it doesn't carry the freshly staged
    // constraint's alias, closure validation fails even though the resolution is correct.
    const opts = { crossFormatLinking: true as const }
    const authority = new MappingAuthority()

    const first = authority.resolve({
      generationId: 'g-corr',
      sourceId: 'dt.log',
      identities: [ipWire('10.230.0.10')],
      correlationOptions: opts,
    })
    expect(first.ok).toBe(true)

    const staged = authority.resolveStaging({
      generationId: 'g-corr',
      sourceId: 'dt.pcap',
      identities: [ipText('10.230.0.10')],
      correlationOptions: opts,
    })
    expect(staged.ok).toBe(true)
    if (!staged.ok) return

    const entry = staged.snapshot.entries.find((e) => e.canonical === '10.230.0.10')
    expect(entry).toBeTruthy()
    const textAlias = aliasForSnapshotConstraintStrict(entry!, {
      kind: 'text-ascii',
      byteLength: '10.230.0.10'.length,
    })
    const wireAlias = aliasForSnapshotConstraintStrict(entry!, { kind: 'ipv4-wire' })
    expect(textAlias).toBeDefined()
    expect(wireAlias).toBeDefined()
    expect(textAlias).not.toBe(wireAlias)

    // Commit should still succeed and preserve both aliases in the published session.
    const committed = authority.commitStaging()
    expect(committed.ok).toBe(true)
    if (!committed.ok) return
    const publishedEntry = committed.snapshot.entries.find((e) => e.canonical === '10.230.0.10')
    expect(publishedEntry?.aliases.length).toBeGreaterThanOrEqual(2)
  })
})

describe('Stage 1 — shareable multi-representation groups', () => {
  it('builds groups for multi-alias session identities without leaking originals', () => {
    const opts = { crossFormatLinking: true as const }
    const authority = new MappingAuthority()
    authority.resolve({
      generationId: 'g',
      sourceId: 't',
      identities: [ipText('10.66.77.88')],
      correlationOptions: opts,
    })
    authority.resolve({
      generationId: 'g',
      sourceId: 'p',
      identities: [ipWire('10.66.77.88')],
      correlationOptions: opts,
    })
    const snap = authority.getPublishedSnapshot()!
    const groups = buildShareableCorrelationGroups(snap)
    expect(groups.length).toBeGreaterThan(0)
    const json = JSON.stringify({ correlationGroups: groups })
    assertShareableManifestHasNoLeaks(json, ['10.66.77.88'])
  })
})

describe('Stage 1 — MappingWorkerClient staging preview vs session publish', () => {
  it('does not publish resolveStaging preview; commitStaging publishes full session', async () => {
    const client = new MappingWorkerClient(createInProcessMappingWorkerFactory())
    const preview = await client.resolveStaging('g', 's1', [ipWire('10.0.0.1')])
    expect(preview.scope).toBe('request')
    expect(client.getPublishedSnapshot()).toBeNull()

    const committed = await client.commitStaging()
    expect(committed.scope).toBe('session')
    expect(client.getPublishedSnapshot()?.entries.map((e) => e.canonical)).toContain('10.0.0.1')

    await client.resolveStaging('g', 's2', [ipWire('10.0.0.2')])
    expect(client.getPublishedSnapshot()?.entries.map((e) => e.canonical)).toEqual(['10.0.0.1'])

    const second = await client.commitStaging()
    expect(second.entries.map((e) => e.canonical).sort()).toEqual(['10.0.0.1', '10.0.0.2'])
    client.terminate()
  })
})
