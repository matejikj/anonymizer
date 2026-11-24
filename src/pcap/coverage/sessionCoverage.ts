/**
 * Build session-level unified coverage + entity occurrence index (Stage 10).
 */

import type { AnalysisResult } from '../protocols/analysis'
import type { PacketDiscoveryResult } from '../discovery/types'
import { buildUnifiedCoverageModel } from './buildUnifiedCoverage'
import { PackedEntityOccurrenceIndex, buildOccurrenceIndexFromIntents } from './entityOccurrenceIndex'
import type { EntityOccurrenceIndex, UnifiedCoverageModel } from './types'

export interface WireEntityOccurrence {
  readonly entityKey: string
  readonly packetIndices: readonly number[]
}

export function buildSessionCoverage(input: {
  packetCount: number
  analysis: AnalysisResult
  packetDiscovery: readonly PacketDiscoveryResult[]
  entityOccurrences?: readonly WireEntityOccurrence[]
  entityIntents?: ReadonlyArray<{ category: string; canonical: string; packetIndex: number }>
}): { unifiedCoverage: UnifiedCoverageModel; entityOccurrenceIndex: EntityOccurrenceIndex } {
  const unifiedCoverage = buildUnifiedCoverageModel({
    packetCount: input.packetCount,
    analysis: input.analysis,
    packetDiscovery: input.packetDiscovery,
    structuralSpans: input.analysis.structuralSpans,
  })

  if (input.entityOccurrences && input.entityOccurrences.length > 0) {
    const lists = new Map<string, readonly number[]>()
    for (const e of input.entityOccurrences) {
      lists.set(e.entityKey, e.packetIndices)
    }
    return {
      unifiedCoverage,
      entityOccurrenceIndex: PackedEntityOccurrenceIndex.fromLists(lists),
    }
  }

  const entityOccurrenceIndex = buildOccurrenceIndexFromIntents(
    input.analysis.entities,
    input.analysis.entityOccurrenceLists,
    (input.entityIntents ?? []).map((i) => ({
      entityKey: `${i.category}:${i.canonical}`,
      packetIndex: i.packetIndex,
    })),
  )

  return { unifiedCoverage, entityOccurrenceIndex }
}

export function entityOccurrencesToWire(index: EntityOccurrenceIndex): WireEntityOccurrence[] {
  const out: WireEntityOccurrence[] = []
  for (const key of index.entityKeys()) {
    out.push({ entityKey: key, packetIndices: [...index.packetsForEntity(key)] })
  }
  return out
}

export function entityOccurrenceListsFromWire(
  wire: readonly WireEntityOccurrence[] | undefined,
): ReadonlyMap<string, readonly number[]> {
  const map = new Map<string, readonly number[]>()
  if (!wire) return map
  for (const e of wire) {
    map.set(e.entityKey, e.packetIndices)
  }
  return map
}
