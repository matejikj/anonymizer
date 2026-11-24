import type {
  DetectorConfig,
  Entity,
  EntitySummary,
  PackedMatchIndex,
  ResolvedMatch,
} from '../domain/types.ts'
import { DEFAULT_DETECTOR_CONFIG } from '../domain/types.ts'
import {
  assertResolvedNonOverlapping,
  assertSameLineCount,
  validateRawMatch,
} from '../domain/invariants.ts'
import { buildLineIndex } from './lineIndex.ts'
import { runAllDetectors } from './detectors/index.ts'
import { resolveOverlaps } from './resolveOverlaps.ts'
import { buildEntityMapFromSnapshot, toEntitySummaries } from './entityRegistry.ts'
import {
  entityKeyToIndex,
  packResolvedMatches,
} from './packedMatchIndex.ts'
import {
  buildReplacementPlan,
  transform,
  transformWithPlan,
  type ReplacementPlan,
} from './transform.ts'
import { createOffsetMap } from './offsetMap.ts'
import type { OffsetMap } from '../domain/types.ts'
import { MappingAuthority } from '../mapping/mappingAuthority.ts'
import { collectTextIdentities } from '../mapping/textIdentity.ts'

export interface AnalysisResult {
  original: string
  lineCount: number
  matches: ResolvedMatch[]
  entities: Entity[]
  entitySummaries: EntitySummary[]
  entitiesByKey: Map<string, Entity>
  packed: PackedMatchIndex
  plan: ReplacementPlan
  offsetMap: OffsetMap
  /** Reference full anonymized text (for tests / small docs). */
  anonymized: string
}

/**
 * Pure detection + transform pipeline (no React, no Worker).
 * Reference path for Krok 2 fixture contract.
 * Stage 18: aliases from in-process MappingAuthority (same engine as mapping worker).
 */
export function analyze(
  original: string,
  config: DetectorConfig = DEFAULT_DETECTOR_CONFIG,
): AnalysisResult {
  const lineIndex = buildLineIndex(original)
  const raw = runAllDetectors(original, lineIndex, config)
  for (const m of raw) validateRawMatch(original, m)

  const matches = resolveOverlaps(raw)
  assertResolvedNonOverlapping(matches)

  const authority = new MappingAuthority()
  const identities = collectTextIdentities(matches, 'sync-analyze')
  const resolved = authority.resolve({
    generationId: 'sync-analyze',
    sourceId: 'sync-analyze',
    identities,
    customRules: config.customRules,
  })
  if (!resolved.ok) {
    throw new Error(resolved.message)
  }

  const { entities, byKey } = buildEntityMapFromSnapshot(matches, resolved.snapshot, config.customRules)
  const entityIndexByKey = entityKeyToIndex(entities)
  const packed = packResolvedMatches(matches, entityIndexByKey, (key) => byKey.get(key)?.enabled ?? true)
  const plan = buildReplacementPlan(packed, entities)
  const offsetMap = createOffsetMap(packed, plan)

  const anonymized = transform(original, matches, byKey)
  const viaPlan = transformWithPlan(original, packed, plan)
  if (anonymized !== viaPlan) {
    throw new Error('Reference transform and replacement plan disagree')
  }
  assertSameLineCount(original, anonymized)

  return {
    original,
    lineCount: lineIndex.lineCount,
    matches,
    entities,
    entitySummaries: toEntitySummaries(entities),
    entitiesByKey: byKey,
    packed,
    plan,
    offsetMap,
    anonymized,
  }
}
