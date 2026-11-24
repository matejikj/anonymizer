import type { Entity, EntitySummary, ResolvedMatch } from '../domain/types.ts'
import type { MappingSnapshot } from '../mapping/types.ts'
import { buildAliasLookup, mappingKey } from '../mapping/types.ts'
import { canonicalizeTextIdentity } from '../mapping/textCanonical.ts'
import type { CustomRule } from '../domain/types.ts'
import {
  applyReplacementsToEntities,
  createEntityRegistry,
  registerEntitySkeletons,
} from './replacements.ts'

export { createEntityRegistry, registerEntitySkeletons, applyReplacementsToEntities }

export function toEntitySummaries(entities: Entity[]): EntitySummary[] {
  return entities.map((e) => ({
    key: e.key,
    category: e.category,
    originalSample: e.originalSample,
    normalized: e.normalized,
    replacement: e.replacement,
    occurrenceCount: e.occurrenceCount,
    enabled: e.enabled,
    source: e.source,
    sourceId: e.sourceId,
    createdOrder: e.createdOrder,
  }))
}

function entityKeyReplacementsFromSnapshot(snapshot: MappingSnapshot): Map<string, string> {
  const lookup = buildAliasLookup(snapshot)
  const out = new Map<string, string>()
  for (const [mapKey, alias] of lookup) {
    const colon = mapKey.indexOf(':')
    if (colon < 0) continue
    const category = mapKey.slice(0, colon)
    const canonical = mapKey.slice(colon + 1)
    out.set(`${category}::${canonical}`, alias)
  }
  return out
}

export function buildEntityMapFromSnapshot(
  matches: ResolvedMatch[],
  snapshot: MappingSnapshot,
  customRules: CustomRule[] = [],
): { entities: Entity[]; byKey: Map<string, Entity> } {
  const registry = createEntityRegistry(customRules)
  const entities = registerEntitySkeletons(registry, matches)
  applyReplacementsToEntities(entities, entityKeyReplacementsFromSnapshot(snapshot))
  return { entities, byKey: registry.entities }
}

/** Legacy path — prefer buildEntityMapFromSnapshot (Stage 18). */
export function buildEntityMap(
  matches: ResolvedMatch[],
  customRules: CustomRule[] = [],
): { entities: Entity[]; byKey: Map<string, Entity> } {
  const registry = createEntityRegistry(customRules)
  const entities = registerEntitySkeletons(registry, matches)
  return { entities, byKey: registry.entities }
}

export function patchEntitySummariesFromSnapshot(
  summaries: EntitySummary[],
  snapshot: MappingSnapshot,
): EntitySummary[] {
  const lookup = buildAliasLookup(snapshot)
  return summaries.map((e) => {
    const canonical = canonicalizeTextIdentity(e.category, e.originalSample) ?? e.normalized
    const alias = lookup.get(mappingKey(e.category, canonical))
    return alias != null ? { ...e, normalized: canonical, replacement: alias } : e
  })
}
