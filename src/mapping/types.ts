/**
 * MappingAuthority domain types (Stage 7 / Stage 18).
 * Application layer receives only immutable MappingSnapshot — never mutable registry.
 */

import type { Category, CustomRule } from '../domain/types'
import type { EntityCategory } from '../pcap/anonymization/entityRegistry'
import type { MappingConfig } from '../pcap/anonymization/mapping'
import type { IdentityCategory } from './identityCategories'
import type { ReverseLookupCandidate } from './reverseIndex'

export type { EntityCategory, MappingConfig, Category, IdentityCategory }

/** Alias relationship to logical identity. */
export type AliasDisposition = 'bijective' | 'ambiguous-fixed' | 'preserved'

/** Detector / rule provenance for a canonical identity. */
export interface IdentitySourceRef {
  readonly detectorId: string
  readonly ruleId?: string
}

/** Packed occurrence reference — no duplicate original string per occurrence. */
export type OccurrenceRef =
  | { readonly kind: 'text'; readonly sourceId: string; readonly line: number; readonly start: number; readonly end: number }
  | { readonly kind: 'packet'; readonly sourceId: string; readonly packetIndex: number }

/** PCAP wire representation constraint — used by plan builder. */
export type WireRepresentationConstraint =
  | { readonly kind: 'ipv4-wire' }
  | { readonly kind: 'ipv6-wire' }
  | { readonly kind: 'mac-wire' }
  | { readonly kind: 'hostname-ascii'; readonly labelCount: number; readonly maxLabelLength: number }
  | { readonly kind: 'port-wire'; readonly protocol: 'tcp' | 'udp' | 'sctp' | 'unknown' }
  | { readonly kind: 'vlan-wire' }
  | { readonly kind: 'radio-id-wire'; readonly bitWidth: 24 }
  | { readonly kind: 'ssrc-wire' }
  | { readonly kind: 'timestamp-wire' }
  | { readonly kind: 'text-ascii'; readonly byteLength: number }

/** One wire-safe alias bound to a representation constraint. */
export interface RepresentationAlias {
  readonly alias: string
  readonly constraint: WireRepresentationConstraint
  readonly disposition: AliasDisposition
}

/** Append-only registry entry (internal to MappingAuthority). */
export interface MappingRegistryEntry {
  identityId: number
  category: IdentityCategory
  canonical: string
  originalSample: string
  aliases: RepresentationAlias[]
  source: IdentitySourceRef
  occurrenceCount: number
  occurrences: OccurrenceRef[]
  primaryDisposition: AliasDisposition
  /** Session-only fingerprint — survives plaintext scrub. */
  fingerprint: string
  /** False after last occurrence removed and plaintext scrubbed from reverse index. */
  plaintextActive: boolean
}

/** Canonical identity pending alias allocation. */
export interface CanonicalIdentity {
  readonly category: IdentityCategory
  /** Normalized canonical key (category-specific). */
  readonly canonical: string
  readonly constraint: WireRepresentationConstraint
  /** Original spelling for length-aware alias generation. */
  readonly originalSpelling?: string
  readonly source?: IdentitySourceRef
  readonly occurrence?: OccurrenceRef
  /** T06 — discovery flow hint for port identities (sip/stun/…). */
  readonly portFlowHint?: import('../pcap/anonymization/portPolicy').PortFlowHint
  /** T06 revision — SDP media mate canonical (`udp/5006`) for this port identity. */
  readonly mediaMateCanonical?: string
}

/** One resolved alias in an immutable snapshot. */
export interface MappingSnapshotEntry {
  readonly identityId: number
  readonly category: IdentityCategory
  readonly canonical: string
  /**
   * Primary alias = first registered representation (`aliases[0]`).
   * Consumers that need a specific wire/text constraint MUST use `aliases`
   * with `aliasForConstraint()` / `aliasForSnapshotConstraint()`, never assume
   * `alias` matches the constraint they are rewriting.
   */
  readonly alias: string
  readonly aliases: readonly RepresentationAlias[]
  readonly constraint: WireRepresentationConstraint
  readonly disposition: AliasDisposition
  readonly source?: IdentitySourceRef
  readonly occurrenceCount: number
}

interface MappingSnapshotBase {
  /** Monotonic mapping revision — alias for mappingRevision (Stage 19). */
  readonly revision: number
  readonly mappingRevision: number
  /** Cross-format canonicalization contract version (Stage 25). */
  readonly canonicalizationVersion: number
  readonly generationId: string
  readonly sourceId: string
  readonly overflow: boolean
  readonly entries: readonly MappingSnapshotEntry[]
}

/**
 * Request-scoped preview from `resolveStaging()` for `SourceAdapter.buildPlan()`.
 * Entries cover the identities of the source currently being planned.
 */
export interface MappingPlanSnapshot extends MappingSnapshotBase {
  readonly scope: 'request'
}

/**
 * Session-scoped published state after `commitStaging()` / `resolve()`.
 * Entries are the full MappingRegistry union (stable identityId, all aliases,
 * disposition, occurrence counts, monotonic revision, ordered by identityId).
 */
export interface MappingSessionSnapshot extends MappingSnapshotBase {
  readonly scope: 'session'
}

export type MappingSnapshot = MappingPlanSnapshot | MappingSessionSnapshot

export function isMappingPlanSnapshot(snapshot: MappingSnapshot): snapshot is MappingPlanSnapshot {
  return snapshot.scope === 'request'
}

export function isMappingSessionSnapshot(snapshot: MappingSnapshot): snapshot is MappingSessionSnapshot {
  return snapshot.scope === 'session'
}

export function requireSessionSnapshot(snapshot: MappingSnapshot): MappingSessionSnapshot {
  if (!isMappingSessionSnapshot(snapshot)) {
    throw new Error('Expected session-scoped mapping snapshot, received request preview')
  }
  return snapshot
}

/** Which consumers may read which snapshot scope. */
export const MAPPING_SNAPSHOT_CONSUMERS = {
  buildPlan: 'request',
  sourcePlan: 'request',
  publishedSnapshot: 'session',
  mappingBundle: 'session',
  shareableManifest: 'session',
  correlationReview: 'session',
} as const satisfies Record<string, 'request' | 'session'>


import type { CrossFormatCategory } from './crossFormat/types'

export interface CorrelationResolveOptions {
  readonly crossFormatLinking?: boolean
  readonly uncorrelatedCategories?: readonly CrossFormatCategory[]
}

export interface ResolveRequest {
  readonly generationId: string
  readonly sourceId: string
  readonly identities: readonly CanonicalIdentity[]
  readonly customRules?: readonly CustomRule[]
  readonly correlationOptions?: CorrelationResolveOptions
}

export type ResolveResult =
  | { readonly ok: true; readonly snapshot: MappingSnapshot }
  | { readonly ok: false; readonly code: ResolveErrorCode; readonly message: string }

export const RESOLVE_ERROR = {
  cancelled: 'cancelled',
  cardinalityOverflow: 'mapping-cardinality-overflow',
  aliasOverflow: 'mapping-alias-overflow',
  occurrenceIndexOverflow: 'mapping-occurrence-index-overflow',
  engineOverflow: 'mapping-engine-overflow',
  invalidIdentity: 'mapping-invalid-identity',
  oversizeBatch: 'mapping-oversize-batch',
  staleGeneration: 'mapping-stale-generation',
  identityNotFound: 'mapping-identity-not-found',
  stagingConflict: 'mapping-staging-conflict',
  stagingEmpty: 'mapping-staging-empty',
} as const

export type ResolveErrorCode = (typeof RESOLVE_ERROR)[keyof typeof RESOLVE_ERROR]

export interface LookupByOriginalRequest {
  readonly category: IdentityCategory
  readonly canonical: string
}

export interface LookupByAliasRequest {
  readonly alias: string
}

export interface ReleaseOccurrenceRequest {
  readonly category: IdentityCategory
  readonly canonical: string
  readonly occurrence: OccurrenceRef
}

export type LookupResult =
  | { readonly ok: true; readonly candidates: readonly ReverseLookupCandidate[] }
  | { readonly ok: false; readonly code: ResolveErrorCode; readonly message: string }

export type ReleaseOccurrenceResult =
  | { readonly ok: true; readonly mappingRevision: number; readonly scrubbed: boolean }
  | { readonly ok: false; readonly code: ResolveErrorCode; readonly message: string }

export function mappingKey(category: IdentityCategory, canonical: string): string {
  return `${category}:${canonical}`
}

// Snapshots are immutable and a fresh object is published per revision, so an object-identity
// cache is safe and needs no invalidation. Hot paths (e.g. per-packet PCAP alias lookups) call
// buildAliasLookup() once per lookup — without this, that rebuilds an O(entries) Map every time.
const aliasLookupCache = new WeakMap<MappingSnapshot, ReadonlyMap<string, string>>()

export function buildAliasLookup(snapshot: MappingSnapshot): ReadonlyMap<string, string> {
  const cached = aliasLookupCache.get(snapshot)
  if (cached) return cached
  const map = new Map<string, string>()
  for (const entry of snapshot.entries) {
    map.set(mappingKey(entry.category, entry.canonical), entry.alias)
  }
  aliasLookupCache.set(snapshot, map)
  return map
}

export function buildMultiAliasLookup(snapshot: MappingSnapshot): ReadonlyMap<string, readonly RepresentationAlias[]> {
  const map = new Map<string, readonly RepresentationAlias[]>()
  for (const entry of snapshot.entries) {
    map.set(mappingKey(entry.category, entry.canonical), entry.aliases)
  }
  return map
}
