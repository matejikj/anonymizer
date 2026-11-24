/**
 * Text identity collection and snapshot application (Stage 18).
 */

import type { CustomRule, Entity, EntitySource, ResolvedMatch } from '../domain/types'
import { canonicalizeTextIdentity, defaultTextWireConstraint } from './textCanonical'
import type { CanonicalIdentity, MappingSnapshot } from './types'
import { buildAliasLookup, mappingKey } from './types'
import { correlationRegistryKey, lookupCrossFormatAlias } from './crossFormat/identityKey'

export interface TextIdentityInput {
  category: ResolvedMatch['category']
  raw: string
  normalized: string
  original: string
  detectorId: string
  ruleId?: string
  line: number
  start: number
  end: number
}

export function textIdentityFromMatch(match: ResolvedMatch, sourceId: string): CanonicalIdentity | null {
  const canonical = canonicalizeTextIdentity(match.category, match.original)
  if (canonical === null) return null
  return {
    category: match.category,
    canonical,
    constraint: defaultTextWireConstraint(match.category, canonical, match.original),
    originalSpelling: match.original,
    source: {
      detectorId: match.detectorId,
      ruleId: match.ruleId,
    },
    occurrence: {
      kind: 'text',
      sourceId,
      line: match.line,
      start: match.start,
      end: match.end,
    },
  }
}

export function collectTextIdentities(
  matches: ResolvedMatch[],
  sourceId: string,
): CanonicalIdentity[] {
  const seen = new Set<string>()
  const out: CanonicalIdentity[] = []
  for (const match of matches) {
    const id = textIdentityFromMatch(match, sourceId)
    if (!id) continue
    const key = correlationRegistryKey(id)
    if (seen.has(key)) continue
    seen.add(key)
    out.push(id)
  }
  return out
}

export function registerEntitiesFromSnapshot(
  matches: ResolvedMatch[],
  snapshot: MappingSnapshot,
  customRules: CustomRule[] = [],
): Entity[] {
  const aliasLookup = buildAliasLookup(snapshot)
  const customRulesById = new Map(customRules.map((r) => [r.id, r]))
  const registry = new Map<string, Entity>()
  const order: string[] = []

  for (const match of matches) {
    const canonical = canonicalizeTextIdentity(match.category, match.original)
    if (canonical === null) continue
    const key = `${match.category}::${canonical}`
    let entity = registry.get(key)
    if (!entity) {
      const source: EntitySource =
        match.detectorId === 'custom.rule' ? 'custom-rule' : 'builtin'
      const constraint = defaultTextWireConstraint(match.category, canonical, match.original)
      const alias =
        lookupCrossFormatAlias(snapshot, match.category, canonical, constraint, match.original) ??
        aliasLookup.get(mappingKey(match.category, canonical)) ??
        ''
      entity = {
        key,
        category: match.category,
        originalSample: match.original,
        normalized: canonical,
        replacement: alias,
        occurrenceCount: 0,
        occurrenceIndexes: new Uint32Array(0),
        enabled: true,
        source,
        sourceId: match.ruleId ?? match.detectorId,
        createdOrder: order.length,
      }
      registry.set(key, entity)
      order.push(key)
    }
    entity.occurrenceCount++
    void customRulesById
  }

  const buckets = new Map<string, number[]>()
  for (let i = 0; i < matches.length; i++) {
    const match = matches[i]!
    const canonical = canonicalizeTextIdentity(match.category, match.original)
    if (canonical === null) continue
    const key = `${match.category}::${canonical}`
    let list = buckets.get(key)
    if (!list) {
      list = []
      buckets.set(key, list)
    }
    list.push(i)
  }
  for (const [key, indexes] of buckets) {
    const entity = registry.get(key)!
    entity.occurrenceIndexes = Uint32Array.from(indexes)
  }

  return order.map((k) => registry.get(k)!)
}

export function applySnapshotToEntitySummaries<
  T extends { key: string; category: Entity['category']; normalized: string; replacement: string },
>(entities: T[], snapshot: MappingSnapshot): T[] {
  const lookup = buildAliasLookup(snapshot)
  return entities.map((e) => {
    const alias =
      lookupCrossFormatAlias(snapshot, e.category, e.normalized, defaultTextWireConstraint(e.category, e.normalized), e.normalized) ??
      lookup.get(mappingKey(e.category, e.normalized))
    return alias != null ? { ...e, replacement: alias } : e
  })
}
