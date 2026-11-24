/**
 * Effective entity/category enable state (ARCHITECTURE §3.3 / Krok 6).
 *
 * - `entity.enabled` = individual preference (never cleared by category master)
 * - `categoryMaster[cat]` = master switch for the category
 * - effective = master && individual
 * - `packed.flags` stores the effective bit used by the replacement plan
 */

import type { Category, Entity, PackedMatchIndex } from '../../domain/types.ts'
import { FLAG_ENABLED } from '../../engine/packedMatchIndex.ts'

export const ALL_CATEGORIES: Category[] = [
  'ip',
  'hostname',
  'sip-phone',
  'email',
  'person',
  'user-id',
  'internal-id',
  'port',
  'custom',
]

export type CategoryMasterMap = Record<Category, boolean>

export function createDefaultCategoryMasters(): CategoryMasterMap {
  const out = {} as CategoryMasterMap
  for (const c of ALL_CATEGORIES) out[c] = true
  return out
}

export function isEffectivelyEnabled(
  entity: { category: Category; enabled: boolean },
  masters: CategoryMasterMap,
): boolean {
  return (masters[entity.category] ?? true) && entity.enabled
}

/** Bitset parallel to entities[]: 1 = effectively enabled. */
export function buildEffectiveEntityBitset(
  entities: Entity[],
  masters: CategoryMasterMap,
): Uint8Array {
  const bits = new Uint8Array(entities.length)
  for (let i = 0; i < entities.length; i++) {
    bits[i] = isEffectivelyEnabled(entities[i]!, masters) ? 1 : 0
  }
  return bits
}

/** Write effective FLAG_ENABLED into packed match flags from entity index + masters. */
export function applyEffectiveMatchFlags(
  packed: PackedMatchIndex,
  entities: Entity[],
  masters: CategoryMasterMap,
): void {
  for (let i = 0; i < packed.starts.length; i++) {
    const ent = entities[packed.entityIndexes[i]!]
    const on = ent ? isEffectivelyEnabled(ent, masters) : false
    packed.flags[i] = on ? FLAG_ENABLED : 0
  }
}

export interface CategorySummary {
  category: Category
  uniqueCount: number
  occurrenceCount: number
  enabledUnique: number
  disabledUnique: number
  /** Master switch (does not erase individual prefs). */
  masterEnabled: boolean
  /** True when master is on but some individuals are off. */
  partiallyDisabled: boolean
}

export function summarizeCategories(
  entities: Entity[],
  masters: CategoryMasterMap,
): CategorySummary[] {
  const map = new Map<Category, CategorySummary>()
  for (const c of ALL_CATEGORIES) {
    map.set(c, {
      category: c,
      uniqueCount: 0,
      occurrenceCount: 0,
      enabledUnique: 0,
      disabledUnique: 0,
      masterEnabled: masters[c] ?? true,
      partiallyDisabled: false,
    })
  }
  for (const e of entities) {
    const row = map.get(e.category)
    if (!row) continue
    row.uniqueCount += 1
    row.occurrenceCount += e.occurrenceCount
    if (e.enabled) row.enabledUnique += 1
    else row.disabledUnique += 1
  }
  const out: CategorySummary[] = []
  for (const c of ALL_CATEGORIES) {
    const row = map.get(c)!
    if (row.uniqueCount === 0) continue
    row.partiallyDisabled =
      row.masterEnabled && row.disabledUnique > 0 && row.enabledUnique > 0
    out.push(row)
  }
  return out
}

export interface ExposedSummary {
  categoryCount: number
  entityCount: number
  occurrenceCount: number
  categories: Array<{
    category: Category
    entityCount: number
    occurrenceCount: number
    reason: 'master-off' | 'individual-off' | 'mixed'
  }>
}

/** Values that will appear in clear text in export/preview (not effectively anonymized). */
export function computeExposedSummary(
  entities: Entity[],
  masters: CategoryMasterMap,
): ExposedSummary {
  const byCat = new Map<
    Category,
    { entityCount: number; occurrenceCount: number; masterOff: boolean; indivOff: boolean }
  >()
  let entityCount = 0
  let occurrenceCount = 0
  for (const e of entities) {
    if (isEffectivelyEnabled(e, masters)) continue
    entityCount += 1
    occurrenceCount += e.occurrenceCount
    let row = byCat.get(e.category)
    if (!row) {
      row = {
        entityCount: 0,
        occurrenceCount: 0,
        masterOff: !(masters[e.category] ?? true),
        indivOff: false,
      }
      byCat.set(e.category, row)
    }
    row.entityCount += 1
    row.occurrenceCount += e.occurrenceCount
    if (!(masters[e.category] ?? true)) row.masterOff = true
    if (!e.enabled) row.indivOff = true
  }
  const categories = [...byCat.entries()].map(([category, row]) => ({
    category,
    entityCount: row.entityCount,
    occurrenceCount: row.occurrenceCount,
    reason:
      row.masterOff && row.indivOff
        ? ('mixed' as const)
        : row.masterOff
          ? ('master-off' as const)
          : ('individual-off' as const),
  }))
  return {
    categoryCount: categories.length,
    entityCount,
    occurrenceCount,
    categories,
  }
}

export type SecurityLevel = 'ok' | 'exposed' | 'blocked'

export function computeSecurityLevel(input: {
  analysisDone: boolean
  failedRuleIds: string[]
  exposed: ExposedSummary
}): SecurityLevel {
  if (!input.analysisDone || input.failedRuleIds.length > 0) return 'blocked'
  if (input.exposed.entityCount > 0) return 'exposed'
  return 'ok'
}
