/**
 * Cross-format identity key resolution and alias lookup (Stage 25).
 */

import type { IdentityCategory } from '../identityCategories'
import type { CanonicalIdentity, MappingSnapshot, WireRepresentationConstraint } from '../types'
import type { CorrelationResolveOptions } from '../types'
import { mappingKey } from '../types'
import { aliasForConstraint } from '../mappingRegistry'
import {
  crossFormatCategoryFromIdentity,
  crossFormatRegistryKeyFromIdentity,
} from './categories'
import { canonicalizeCrossFormatCategory } from './canonicalizers'
import type { CrossFormatCategory } from './types'

function isUncorrelatedCategory(
  category: IdentityCategory,
  raw: string,
  constraint: WireRepresentationConstraint | undefined,
  options?: CorrelationResolveOptions,
): CrossFormatCategory | null {
  if (!options?.uncorrelatedCategories?.length) return null
  const cf = crossFormatCategoryFromIdentity(category, raw, constraint)
  if (cf && options.uncorrelatedCategories.includes(cf)) return cf
  return null
}

export function registryKeyForResolve(
  identity: CanonicalIdentity,
  options?: CorrelationResolveOptions,
): string {
  const raw = identity.originalSpelling ?? identity.canonical
  if (isUncorrelatedCategory(identity.category, raw, identity.constraint, options)) {
    return mappingKey(identity.category, identity.canonical)
  }
  return correlationRegistryKey(identity)
}

export function correlationRegistryKey(identity: CanonicalIdentity): string {
  const cfKey = crossFormatRegistryKeyFromIdentity(
    identity.category,
    identity.originalSpelling ?? identity.canonical,
    identity.constraint,
  )
  if (cfKey) return cfKey
  return mappingKey(identity.category, identity.canonical)
}

export function correlationRegistryKeyFromParts(
  category: IdentityCategory,
  canonical: string,
  constraint?: WireRepresentationConstraint,
  originalSpelling?: string,
): string {
  const cfKey = crossFormatRegistryKeyFromIdentity(category, originalSpelling ?? canonical, constraint)
  if (cfKey) return cfKey
  return mappingKey(category, canonical)
}

export function findSnapshotEntryForIdentity(
  snapshot: MappingSnapshot,
  category: IdentityCategory,
  canonical: string,
  constraint?: WireRepresentationConstraint,
  originalSpelling?: string,
): MappingSnapshot['entries'][number] | undefined {
  const key = correlationRegistryKeyFromParts(category, canonical, constraint, originalSpelling)
  for (const entry of snapshot.entries) {
    const entryKey = correlationRegistryKeyFromParts(
      entry.category,
      entry.canonical,
      entry.constraint,
      entry.canonical,
    )
    if (entryKey === key) return entry
  }
  return snapshot.entries.find((e) => mappingKey(e.category, e.canonical) === mappingKey(category, canonical))
}

export function lookupCrossFormatAlias(
  snapshot: MappingSnapshot,
  category: IdentityCategory,
  canonical: string,
  constraint?: WireRepresentationConstraint,
  originalSpelling?: string,
): string | undefined {
  const entry = findSnapshotEntryForIdentity(snapshot, category, canonical, constraint, originalSpelling)
  if (!entry) return undefined
  if (constraint) {
    return aliasForConstraint(
      {
        identityId: entry.identityId,
        category: entry.category,
        canonical: entry.canonical,
        originalSample: entry.canonical,
        aliases: [...entry.aliases],
        source: entry.source ?? { detectorId: 'unknown' },
        occurrenceCount: entry.occurrenceCount,
        occurrences: [],
        primaryDisposition: entry.disposition,
        fingerprint: '',
        plaintextActive: true,
      },
      constraint,
    )
  }
  return entry.alias
}

export function buildCrossFormatAliasLookup(snapshot: MappingSnapshot): ReadonlyMap<string, string> {
  const map = new Map<string, string>()
  for (const entry of snapshot.entries) {
    const key = correlationRegistryKeyFromParts(entry.category, entry.canonical, entry.constraint, entry.canonical)
    map.set(key, entry.alias)
    map.set(mappingKey(entry.category, entry.canonical), entry.alias)
  }
  return map
}

export function crossFormatCanonicalForIdentity(identity: CanonicalIdentity): {
  category: import('./types').CrossFormatCategory
  canonical: string
} | null {
  const cf = crossFormatCategoryFromIdentity(
    identity.category,
    identity.originalSpelling ?? identity.canonical,
    identity.constraint,
  )
  if (!cf) return null
  const source =
    identity.category === 'ip' ||
    identity.category === 'hostname' ||
    identity.constraint.kind === 'text-ascii'
      ? 'text'
      : 'pcap'
  const canonical = canonicalizeCrossFormatCategory(cf, identity.originalSpelling ?? identity.canonical, source)
  if (!canonical) return null
  return { category: cf, canonical }
}
