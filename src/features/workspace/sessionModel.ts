/**
 * Session model lives outside React/Zustand (ARCHITECTURE §5.2 / §9.1).
 * At most one large log session is retained at a time.
 */

import { Text } from '@codemirror/state'
import type { Entity, EntitySummary, PackedMatchIndex, Category } from '../../domain/types.ts'
import type { ReplacementPlan } from '../../engine/transform.ts'
import { buildReplacementPlan } from '../../engine/transform.ts'
import {
  fromTransferableBuffers,
  type PackedMatchBuffers,
} from '../../engine/packedMatchIndex.ts'
import type { LogMode } from '../import-log/preflight.ts'
import { findOversizedLines } from '../import-log/preflight.ts'
import type { DetectionResult } from '../../app/workerClient.ts'
import {
  createDefaultCategoryMasters,
  applyEffectiveMatchFlags,
  type CategoryMasterMap,
} from '../review/entityState.ts'
import { packLineEndingsFromText } from '../export-log/lineEndings.ts'
import {
  EMPTY_INCIDENT_LOG_SNAPSHOT,
  type IncidentLogSnapshot,
} from '../../domain/anonymizationIncident.ts'

export interface SessionMeta {
  fileName: string | null
  byteLength: number
  lineCount: number
  mode: LogMode
  generation: string
  oversizedLines: number[]
  entityCount: number
  matchCount: number
  failedRuleIds: string[]
}

export interface SessionModel {
  doc: Text
  /** UTF-16 original string (same content as doc; LF-normalized for CodeMirror). */
  original: string
  /**
   * Original physical line endings (ARCHITECTURE §7.5) — parallel to physical lines
   * of the pre-normalized source. Export restores these onto the anonymized LF text.
   */
  lineEndings: Uint8Array
  packed: PackedMatchIndex
  plan: ReplacementPlan
  entities: Entity[]
  entitySummaries: EntitySummary[]
  meta: SessionMeta
  /** Category master switches (ARCHITECTURE §3.3). */
  categoryMasters: CategoryMasterMap
  /** Bumped on every plan mutation so editors can refresh decorations. */
  planRevision: number
  /**
   * True when Detection Worker still holds the same match set as this session
   * (false after main-thread CRLF re-analysis).
   */
  workerPlanTrusted: boolean
  /** T07 — value-free line isolation incidents (preview == export mask source). */
  incidents: IncidentLogSnapshot
}

let active: SessionModel | null = null

export function getSessionModel(): SessionModel | null {
  return active
}

export function clearSessionModel(): void {
  active = null
}

/** E2E / tests: mark analysis failed so export stays blocked (ARCHITECTURE §3.5). */
export function markSessionAnalysisFailed(ruleIds: string[]): boolean {
  if (!active) return false
  active.meta.failedRuleIds = [...ruleIds]
  return true
}

function summariesToEntities(summaries: EntitySummary[]): Entity[] {
  return summaries.map((s) => ({
    key: s.key,
    category: s.category,
    originalSample: s.originalSample,
    normalized: s.normalized,
    replacement: s.replacement,
    occurrenceCount: s.occurrenceCount,
    occurrenceIndexes: new Uint32Array(0),
    enabled: s.enabled,
    source: s.source,
    sourceId: s.sourceId,
    createdOrder: s.createdOrder,
  }))
}

export function buildSessionModel(input: {
  text: string
  detection: DetectionResult
  fileName: string | null
  byteLength: number
  mode: LogMode
  workerPlanTrusted?: boolean
  /** Endings from pre-normalized source; defaults to LF for each line of `text`. */
  lineEndings?: Uint8Array
}): SessionModel {
  const packed = fromTransferableBuffers(input.detection.packedMatches)
  const entities = summariesToEntities(input.detection.entities)
  const categoryMasters = createDefaultCategoryMasters()
  applyEffectiveMatchFlags(packed, entities, categoryMasters)
  const plan = buildReplacementPlan(packed, entities)
  const oversizedLines = findOversizedLines(input.text)
  const lineEndings = input.lineEndings ?? packLineEndingsFromText(input.text)
  const model: SessionModel = {
    doc: Text.of(input.text.split('\n')),
    original: input.text,
    lineEndings,
    packed,
    plan,
    entities,
    entitySummaries: input.detection.entities,
    categoryMasters,
    planRevision: 1,
    workerPlanTrusted: input.workerPlanTrusted !== false,
    incidents: input.detection.incidents ?? EMPTY_INCIDENT_LOG_SNAPSHOT,
    meta: {
      fileName: input.fileName,
      byteLength: input.byteLength,
      lineCount: input.detection.lineCount,
      mode: input.mode,
      generation: input.detection.requestId,
      oversizedLines,
      entityCount: entities.length,
      matchCount: packed.starts.length,
      failedRuleIds: [...input.detection.failedRuleIds],
    },
  }
  // Replace atomically — never keep two large models.
  active = model
  return model
}

/** Rebuild plan after entity enable flags change. */
export function rebuildSessionPlan(entities?: Entity[]): ReplacementPlan | null {
  if (!active) return null
  if (entities) {
    active.entities = entities
    active.entitySummaries = entities.map((e) => ({
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
  applyEffectiveMatchFlags(active.packed, active.entities, active.categoryMasters)
  active.plan = buildReplacementPlan(active.packed, active.entities)
  active.planRevision += 1
  return active.plan
}

export type { PackedMatchBuffers, Category }
