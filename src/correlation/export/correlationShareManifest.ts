/**
 * AI-shareable correlation manifest — leak-safe subset (Stage 29).
 * Separate from internal CorrelationSessionManifest (Stage 24).
 */

import type { IdentityCategory } from '../../mapping/identityCategories'
import type { MappingSessionSnapshot, MappingSnapshot } from '../../mapping/types'
import { requireSessionSnapshot } from '../../mapping/types'
import { SourceKind as SK } from '../../domain/sourceArtifact'
import type { CorrelationSourceRecord, PcapSourceDiscovery } from '../types'

export const SHAREABLE_MANIFEST_FILE_NAME = 'correlation-manifest.json'

export interface ShareableSourceEntry {
  readonly sourceId: string
  readonly outputFileName: string
  readonly kind: 'text' | 'pcap'
  readonly timeRange?: { readonly startMs: number; readonly endMs: number }
}

export interface ShareableCorrelationGroup {
  readonly tag: string
  readonly category: IdentityCategory
  readonly aliases: readonly string[]
}

export interface ShareableCorrelationManifest {
  readonly format: 'rnd-log-anonymizer-correlation-manifest'
  readonly schemaVersion: 1
  readonly partial: boolean
  readonly sources: readonly ShareableSourceEntry[]
  readonly correlationGroups?: readonly ShareableCorrelationGroup[]
}

let tagCounter = 0

function nextCorrelationTag(): string {
  tagCounter += 1
  const rand = Math.random().toString(16).slice(2, 10)
  return `c${tagCounter.toString(36)}-${rand}`
}

function pcapTimeRange(discovery: PcapSourceDiscovery): { startMs: number; endMs: number } | undefined {
  const descriptors = discovery.container.descriptors
  if (descriptors.length === 0) return undefined
  let startMs = Number.POSITIVE_INFINITY
  let endMs = Number.NEGATIVE_INFINITY
  for (const d of descriptors) {
    const seconds =
      Number(d.timestamp.offsetSeconds) + Number(d.timestamp.ticks / d.timestamp.unitsPerSecond)
    const ts = seconds * 1000
    if (ts < startMs) startMs = ts
    if (ts > endMs) endMs = ts
  }
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) return undefined
  return { startMs, endMs }
}

export function buildShareableSourceEntries(
  sources: readonly CorrelationSourceRecord[],
): ShareableSourceEntry[] {
  const entries: ShareableSourceEntry[] = []
  for (const source of sources) {
    if (source.phase !== 'planned' || source.exportState !== 'ready') continue
    if (source.kind === SK.Text && source.discovery?.kind === 'text') {
      entries.push({
        sourceId: source.sourceId,
        outputFileName: source.outputFileName,
        kind: 'text',
      })
      continue
    }
    if (source.kind === SK.Pcap && source.discovery?.kind === 'pcap') {
      entries.push({
        sourceId: source.sourceId,
        outputFileName: source.outputFileName,
        kind: 'pcap',
        timeRange: pcapTimeRange(source.discovery),
      })
    }
  }
  return entries
}

export function buildShareableCorrelationGroups(
  snapshot: MappingSessionSnapshot | MappingSnapshot,
): ShareableCorrelationGroup[] {
  const session = requireSessionSnapshot(snapshot)
  const groups: ShareableCorrelationGroup[] = []
  for (const entry of session.entries) {
    if (entry.aliases.length <= 1) continue
    const aliases = [...new Set(entry.aliases.map((a) => a.alias))].sort()
    if (aliases.length <= 1) continue
    groups.push({
      tag: nextCorrelationTag(),
      category: entry.category,
      aliases,
    })
  }
  return groups
}

export function needsShareableCorrelationManifest(snapshot: MappingSessionSnapshot | MappingSnapshot): boolean {
  return buildShareableCorrelationGroups(snapshot).length > 0
}

export function buildShareableCorrelationManifest(input: {
  sources: readonly CorrelationSourceRecord[]
  snapshot: MappingSessionSnapshot | MappingSnapshot
  partial: boolean
}): ShareableCorrelationManifest | null {
  const sourceEntries = buildShareableSourceEntries(input.sources)
  if (sourceEntries.length === 0) return null

  const correlationGroups = buildShareableCorrelationGroups(input.snapshot)
  const manifest: ShareableCorrelationManifest = {
    format: 'rnd-log-anonymizer-correlation-manifest',
    schemaVersion: 1,
    partial: input.partial,
    sources: sourceEntries,
  }
  if (correlationGroups.length > 0) {
    return { ...manifest, correlationGroups }
  }
  return manifest
}

const FORBIDDEN_MANIFEST_PATTERNS: RegExp[] = [
  /\bcanonical\b/i,
  /\bfingerprint\b/i,
  /\bpassphrase\b/i,
  /\bmappingRevision\b/,
  /\bmappingSeed\b/i,
  /\bidentityId\b/,
  /\boccurrence\b/i,
  /\boriginalSample\b/,
  /\brnd-mapping-bundle\b/,
]

/** Reject manifests that accidentally embed private mapping or original identifiers. */
export function assertShareableManifestHasNoLeaks(
  manifestJson: string,
  forbiddenSamples: readonly string[] = [],
): void {
  for (const pattern of FORBIDDEN_MANIFEST_PATTERNS) {
    if (pattern.test(manifestJson)) {
      throw new Error(`Shareable manifest must not contain forbidden pattern: ${pattern}`)
    }
  }
  // Output names often retain substrings of originals (host in filename). Those are not
  // mapping leaks — scrub them before sample scan.
  const scrubbed = manifestJson.replace(/"outputFileName"\s*:\s*"(?:\\.|[^"\\])*"/g, '"outputFileName":""')
  for (const sample of forbiddenSamples) {
    if (sample.length >= 4 && scrubbed.includes(sample)) {
      throw new Error('Shareable manifest must not contain original identifier sample')
    }
  }
}

export function resetShareableManifestCounterForTests(): void {
  tagCounter = 0
}
