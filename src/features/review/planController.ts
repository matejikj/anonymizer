/**
 * Session plan updates for entity/category toggles — no redetection (ARCHITECTURE §7.5).
 */

import type { Category } from '../../domain/types.ts'
import { buildReplacementPlan } from '../../engine/transform.ts'
import { fenwickBuild } from '../../engine/fenwick.ts'
import { FLAG_ENABLED } from '../../engine/packedMatchIndex.ts'
import type { ReplacementPlanBuffers } from '../../workers/protocol.ts'
import {
  applyEffectiveMatchFlags,
  buildEffectiveEntityBitset,
  createDefaultCategoryMasters,
  isEffectivelyEnabled,
  type CategoryMasterMap,
} from './entityState.ts'
import { getSessionModel, type SessionModel } from '../workspace/sessionModel.ts'

export function ensureCategoryMasters(session: SessionModel): CategoryMasterMap {
  if (!session.categoryMasters) {
    session.categoryMasters = createDefaultCategoryMasters()
  }
  return session.categoryMasters
}

/** Toggle one entity's individual preference; rebuild plan on the main thread. */
export function toggleEntityEnabled(entityKey: string, enabled: boolean): boolean {
  const session = getSessionModel()
  if (!session) return false
  const masters = ensureCategoryMasters(session)
  const entity = session.entities.find((e) => e.key === entityKey)
  if (!entity || entity.enabled === enabled) return false
  entity.enabled = enabled
  // New array identities so React Compiler / memoized lists pick up the change.
  session.entities = session.entities.map((e) =>
    e.key === entityKey ? { ...e, enabled } : e,
  )
  session.entitySummaries = session.entitySummaries.map((e) =>
    e.key === entityKey ? { ...e, enabled } : e,
  )

  applyEffectiveMatchFlags(session.packed, session.entities, masters)
  session.plan = buildReplacementPlan(session.packed, session.entities)
  session.planRevision += 1
  return true
}

/**
 * Set category master switch; preserves individual entity.enabled values.
 * Returns effective entity bitset for optional Worker rebuild.
 */
export function setCategoryMaster(category: Category, enabled: boolean): Uint8Array | null {
  const session = getSessionModel()
  if (!session) return null
  const masters = ensureCategoryMasters(session)
  if (masters[category] === enabled) return null
  masters[category] = enabled
  session.categoryMasters = { ...masters }
  applyEffectiveMatchFlags(session.packed, session.entities, masters)
  session.plan = buildReplacementPlan(session.packed, session.entities)
  session.planRevision += 1
  return buildEffectiveEntityBitset(session.entities, masters)
}

/** Apply transferable plan summary from Worker without clobbering individual prefs. */
export function applyWorkerPlanBuffers(buffers: ReplacementPlanBuffers): boolean {
  const session = getSessionModel()
  if (!session) return false
  const n = buffers.count
  if (n !== session.packed.starts.length) return false

  const enabledFlags = new Uint8Array(buffers.enabledFlags)
  const lengthDeltas = new Int32Array(buffers.lengthDeltas)
  const fenwick =
    buffers.fenwick.byteLength >= (n + 1) * 4
      ? new Int32Array(buffers.fenwick)
      : fenwickBuild(lengthDeltas)

  const replacements: Array<string | null> = new Array(n)
  for (let i = 0; i < n; i++) {
    const on = enabledFlags[i] === 1
    session.packed.flags[i] = on ? FLAG_ENABLED : 0
    const ent = session.entities[session.packed.entityIndexes[i]!]
    replacements[i] = on && ent ? ent.replacement : null
  }
  session.plan = { replacements, lengthDeltas, fenwick }
  session.planRevision += 1
  return true
}

export function snapshotEffectiveBitset(): Uint8Array | null {
  const session = getSessionModel()
  if (!session) return null
  return buildEffectiveEntityBitset(session.entities, session.categoryMasters)
}

export function getPlanRevision(): number {
  return getSessionModel()?.planRevision ?? 0
}

export function entityEffectiveEnabled(entityKey: string): boolean {
  const session = getSessionModel()
  if (!session) return false
  const masters = ensureCategoryMasters(session)
  const entity = session.entities.find((e) => e.key === entityKey)
  return entity ? isEffectivelyEnabled(entity, masters) : false
}

export type { CategoryMasterMap }
