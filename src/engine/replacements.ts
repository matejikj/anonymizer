import type { Category, CustomRule, Entity, EntitySource, ResolvedMatch } from '../domain/types.ts'
import { assertNoNewline } from '../domain/invariants.ts'
import {
  createTextReplacementCounters,
  generateTextAlias,
  type TextReplacementCounters,
} from '../mapping/textAliasEngine.ts'

export type ReplacementCounters = TextReplacementCounters

export function createReplacementCounters(): ReplacementCounters {
  return createTextReplacementCounters()
}

/**
 * @deprecated Stage 18 — use MappingAuthority via textMappingPort. Kept for unit tests of alias shape.
 */
export function nextReplacement(
  category: Category,
  original: string,
  counters: ReplacementCounters,
  customRule?: CustomRule,
): string {
  return generateTextAlias(category, original, counters, customRule)
}

export interface EntityRegistry {
  entities: Map<string, Entity>
  /** Stable creation order list for summaries. */
  order: string[]
  counters: ReplacementCounters
  customRulesById: Map<string, CustomRule>
}

export function createEntityRegistry(customRules: CustomRule[] = []): EntityRegistry {
  return {
    entities: new Map(),
    order: [],
    counters: createReplacementCounters(),
    customRulesById: new Map(customRules.map((r) => [r.id, r])),
  }
}

/**
 * Register entity skeletons without pseudonyms (Stage 18).
 * Replacements are filled later from MappingSnapshot.
 */
export function registerEntitySkeletons(
  registry: EntityRegistry,
  matches: ResolvedMatch[],
): Entity[] {
  for (const match of matches) {
    let entity = registry.entities.get(match.entityKey)
    if (!entity) {
      const source: EntitySource =
        match.detectorId === 'custom.rule' ? 'custom-rule' : 'builtin'
      entity = {
        key: match.entityKey,
        category: match.category,
        originalSample: match.original,
        normalized: match.normalized,
        replacement: '',
        occurrenceCount: 0,
        occurrenceIndexes: new Uint32Array(0),
        enabled: true,
        source,
        sourceId: match.ruleId ?? match.detectorId,
        createdOrder: registry.order.length,
      }
      registry.entities.set(match.entityKey, entity)
      registry.order.push(match.entityKey)
    }
    entity.occurrenceCount++
  }

  const buckets = new Map<string, number[]>()
  for (let i = 0; i < matches.length; i++) {
    const key = matches[i]!.entityKey
    let list = buckets.get(key)
    if (!list) {
      list = []
      buckets.set(key, list)
    }
    list.push(i)
  }
  for (const [key, indexes] of buckets) {
    const entity = registry.entities.get(key)!
    entity.occurrenceIndexes = Uint32Array.from(indexes)
  }

  return registry.order.map((k) => registry.entities.get(k)!)
}

/**
 * Apply MappingAuthority aliases to registered entities.
 */
export function applyReplacementsToEntities(
  entities: Entity[],
  replacements: ReadonlyMap<string, string>,
): void {
  for (const entity of entities) {
    const alias = replacements.get(entity.key)
    if (alias != null) {
      assertNoNewline(alias, 'replacement')
      entity.replacement = alias
    }
  }
}

/**
 * @deprecated Stage 18 — use registerEntitySkeletons + MappingAuthority snapshot.
 */
export function registerEntities(
  registry: EntityRegistry,
  matches: ResolvedMatch[],
): Entity[] {
  for (const match of matches) {
    let entity = registry.entities.get(match.entityKey)
    if (!entity) {
      const source: EntitySource =
        match.detectorId === 'custom.rule' ? 'custom-rule' : 'builtin'
      const rule =
        match.ruleId != null ? registry.customRulesById.get(match.ruleId) : undefined
      const replacement = nextReplacement(
        match.category,
        match.original,
        registry.counters,
        rule,
      )
      assertNoNewline(replacement, 'replacement')
      entity = {
        key: match.entityKey,
        category: match.category,
        originalSample: match.original,
        normalized: match.normalized,
        replacement,
        occurrenceCount: 0,
        occurrenceIndexes: new Uint32Array(0),
        enabled: true,
        source,
        sourceId: match.ruleId ?? match.detectorId,
        createdOrder: registry.order.length,
      }
      registry.entities.set(match.entityKey, entity)
      registry.order.push(match.entityKey)
    }
    entity.occurrenceCount++
  }

  const buckets = new Map<string, number[]>()
  for (let i = 0; i < matches.length; i++) {
    const key = matches[i]!.entityKey
    let list = buckets.get(key)
    if (!list) {
      list = []
      buckets.set(key, list)
    }
    list.push(i)
  }
  for (const [key, indexes] of buckets) {
    const entity = registry.entities.get(key)!
    entity.occurrenceIndexes = Uint32Array.from(indexes)
  }

  return registry.order.map((k) => registry.entities.get(k)!)
}
