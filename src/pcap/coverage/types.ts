/**
 * Unified coverage model (Stage 10) — single authoritative read model.
 */

import type { CoverageStatus } from '../sanitize/types'

export type UnifiedCoverageSource = 'structural' | 'sanitizer'

export type UnifiedCoverageStatus = CoverageStatus

export interface UnifiedLayerCoverage {
  readonly packetIndex: number
  readonly protocol: string
  readonly source: UnifiedCoverageSource
  readonly offset: number
  readonly length: number
  readonly status: UnifiedCoverageStatus
  readonly issues: readonly string[]
}

export interface UnifiedProtocolSummary {
  readonly protocol: string
  readonly packetCount: number
  readonly spanCount: number
  readonly unsupportedCount: number
  readonly structuralSpanCount: number
  readonly sanitizerSpanCount: number
  readonly dominantStatus: UnifiedCoverageStatus
  readonly issues: readonly string[]
}

export interface UnifiedCoverageModel {
  readonly perPacket: readonly (readonly UnifiedLayerCoverage[])[]
  readonly byProtocol: readonly UnifiedProtocolSummary[]
  readonly histogram: ReadonlyMap<string, number>
  readonly totalUnsupportedSpans: number
  readonly totalTruncatedSpans: number
  readonly totalHeuristicSpans: number
}

export interface EntityOccurrenceIndex {
  readonly overflow: boolean
  readonly byteSize: number
  packetsForEntity(entityKey: string): readonly number[]
  hasEntity(entityKey: string, packetIndex: number): boolean
  entityKeys(): IterableIterator<string>
}
