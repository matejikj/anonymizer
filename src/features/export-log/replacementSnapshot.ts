/**
 * Replacement snapshot shared by anonymized viewport and export (ARCHITECTURE §4 / §7.5).
 */

import type { Entity, PackedMatchIndex } from '../../domain/types.ts'
import type { ReplacementPlan } from '../../engine/transform.ts'
import type { ReplacementSnapshot } from '../../workers/protocol.ts'
import { getSessionModel, type SessionModel } from '../workspace/sessionModel.ts'

export type ExportPlanSnapshot = {
  plan: ReplacementPlan
  packed: PackedMatchIndex
  entities: Entity[]
  original: string
  lineEndings: Uint8Array
  planRevision: number
  fileName: string | null
  mode: 'common' | 'large'
  byteLength: number
}

/** Immutable view of the current session plan used by UI + export. */
export function getExportPlanSnapshot(
  session: SessionModel | null = getSessionModel(),
): ExportPlanSnapshot | null {
  if (!session) return null
  return {
    plan: session.plan,
    packed: session.packed,
    entities: session.entities,
    original: session.original,
    lineEndings: session.lineEndings,
    planRevision: session.planRevision,
    fileName: session.meta.fileName,
    mode: session.meta.mode,
    byteLength: session.meta.byteLength,
  }
}

/**
 * Worker start payload: per-entity replacement strings + enable bitset
 * (chunk path also sends per-match window replacements for exact plan parity).
 */
export function buildReplacementSnapshot(session: SessionModel): ReplacementSnapshot {
  return buildReplacementSnapshotFromPlan(getExportPlanSnapshot(session)!)
}

export function buildReplacementSnapshotFromPlan(snapshot: ExportPlanSnapshot): ReplacementSnapshot {
  const replacements = snapshot.entities.map((e) => e.replacement)
  const entityEnabled = new Uint8Array(snapshot.entities.length)
  for (let i = 0; i < snapshot.entities.length; i++) {
    entityEnabled[i] = snapshot.entities[i]!.enabled ? 1 : 0
  }
  return {
    replacements,
    entityEnabled: entityEnabled.buffer.slice(
      entityEnabled.byteOffset,
      entityEnabled.byteOffset + entityEnabled.byteLength,
    ),
  }
}
