/**
 * PCAP discovery model (Stage 8) — canonical identities and transformation intents.
 * Discovery never allocates pseudonyms; aliases come from MappingSnapshot at plan time.
 */

import type { IdentityCategory } from '../../mapping/identityCategories'
import type { WireRepresentationConstraint } from '../../mapping/types'
import type { PortFlowHint } from '../anonymization/portPolicy.ts'
import type {
  AnalysisResult,
  CoverageEntry,
  EntityEntry,
  PacketSummary,
} from '../protocols/analysis'
import type { UnifiedCoverageModel } from '../coverage/types'
import type { EntityOccurrenceIndex } from '../coverage/types'
import type { BytePatch, DeferredPatchContext, LayerCoverage } from '../sanitize/types'
import type { FrozenPacketPlan } from '../kernel/frozenPlan'

export type TransformationIntent =
  | EntityReplacementIntent
  | FixedRedactionIntent
  | TruncationIntent
  | DropRecordIntent
  | MaskRangeIntent

export interface EntityReplacementIntent {
  readonly kind: 'entity-replacement'
  readonly packetIndex: number
  readonly offset: number
  readonly byteLength: number
  readonly category: IdentityCategory
  readonly canonical: string
  readonly constraint: WireRepresentationConstraint
  readonly originalSpelling?: string
}

export interface FixedRedactionIntent {
  readonly kind: 'fixed-redaction'
  readonly packetIndex: number
  readonly offset: number
  readonly byteLength: number
}

export interface TruncationIntent {
  readonly kind: 'truncation'
  readonly packetIndex: number
  readonly truncatedLength: number
}

export interface DropRecordIntent {
  readonly kind: 'drop-record'
  readonly packetIndex: number
}

/** In-place payload mask — keeps packet length; replaces [offset, offset+byteLength). */
export interface MaskRangeIntent {
  readonly kind: 'mask-range'
  readonly packetIndex: number
  readonly offset: number
  readonly byteLength: number
  readonly reason: string
  readonly protocol: string
}

export interface PacketDiscoveryResult {
  readonly packetIndex: number
  readonly packetNumber: number
  readonly intents: readonly TransformationIntent[]
  /** T06 — content-derived port roles collected during this packet's discovery. */
  readonly portFlowHints?: ReadonlyMap<string, PortFlowHint>
  /** T06 revision — SDP media mates collected on this packet. */
  readonly mediaPortPairs?: ReadonlyMap<string, string>
  readonly coverage: readonly LayerCoverage[]
  readonly issues: readonly string[]
  readonly drop: boolean
  readonly truncatedLength?: number
  /**
   * T-01 frozen plan — symbolic ops + legacy deferred bridge; does not retain packet payloads.
   */
  readonly frozenPlan?: FrozenPacketPlan
  /**
   * PF-06 / T-01: materializes this packet's final patches against a real mapping/fingerprint
   * context, without re-running the structural decode that discovery already did (with a
   * throwaway passthrough mapping) to produce the fields above. Only present on the
   * worker-retained discovery result plan-build actually resolves against — the main-thread
   * copy reconstructed from the wire summary (containerWireAdapter.ts) never needs it, since
   * plan-building always happens in the worker against its own retained session.
   */
  readonly resolvePatches?: (ctx: DeferredPatchContext) => BytePatch[]
  /**
   * T07 — isolation decision taken during discovery (plan must apply the same fallback).
   * Absent when the packet sanitized normally.
   */
  readonly isolationFallback?: {
    readonly unit: 'payload' | 'packet'
    readonly reason: 'sanitizer-exception' | 'unknown'
  }
}

export interface ExactOccurrence {
  readonly entityKey: string
  readonly category: IdentityCategory
  readonly canonical: string
  readonly packetIndex: number
  readonly packetNumber: number
}

/** Packed discovery output — no long-term packet payload copies. */
export interface SourceDiscovery {
  readonly generationId: string
  readonly sourceId: string
  readonly totalPackets: number
  readonly analysis: AnalysisResult
  readonly intents: readonly TransformationIntent[]
  readonly packetDiscovery: readonly PacketDiscoveryResult[]
  /** T06 — merged port flow hints (canonical `udp/5070` → sip). */
  readonly portFlowHints: ReadonlyMap<string, PortFlowHint>
  /** T06 revision — SDP media mates (`udp/5004` → `udp/5006`). */
  readonly mediaPortPairs: ReadonlyMap<string, string>
  readonly exactOccurrences: readonly ExactOccurrence[]
  readonly unifiedCoverage: UnifiedCoverageModel
  readonly entityOccurrenceIndex: EntityOccurrenceIndex
}

export interface SourceDiscoverySummary {
  readonly generationId: string
  readonly sourceId: string
  readonly totalPackets: number
  readonly decodedPackets: number
  readonly entityCount: number
  readonly intentCount: number
  readonly entityOverflow: boolean
  readonly coverage: readonly CoverageEntry[]
  readonly entities: readonly EntityEntry[]
  readonly summaries: readonly PacketSummary[]
}
