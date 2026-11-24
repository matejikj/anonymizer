/**
 * Multi-source correlation contracts (Stage 23 / task-1 §4.4).
 * Pure domain — no React, Zustand, or UI imports.
 */

import type { RulesetConfig } from '../domain/configSchema'
import type { WireCoverageRollup } from '../pcap/processing/packedCaptureWire'
import type { PackedMatchIndex, ResolvedMatch } from '../domain/types'
import type { SourceKind } from '../domain/sourceArtifact'
import type { CanonicalIdentity, MappingSnapshot } from '../mapping/types'
import type { ReplacementPlan } from '../engine/transform'
import type { DetectionResult } from '../app/workerClient'
import type { SourceDiscovery } from '../pcap/discovery/types'
import type { PcapPlanSnapshot } from '../pcap/export/planSnapshot'
import type {
  CaptureFormat,
  ClassicPcapHeader,
  PacketRecordDescriptor,
  ParseIssue,
  PcapngInterfaceInfo,
  PcapngSectionInfo,
  SparseCheckpoint,
} from '../pcap/domain/types'
import type { SanitizationPolicy } from '../pcap/sanitize/types'

/** Extended kind for test-only adapters registered in conformance suite. */
export type AdapterKind = SourceKind | 'test'

export interface SourceLimits {
  readonly maxFileBytes: number
  readonly maxSources: number
  readonly maxAggregateBytes: number
}

export type ProbeResult =
  | { readonly ok: true; readonly kind: AdapterKind }
  | { readonly ok: false; readonly code: string; readonly message: string }

export type SourcePreflightResult =
  | { readonly ok: true; readonly byteLength: number; readonly kind: AdapterKind }
  | { readonly ok: false; readonly code: string; readonly message: string }

export interface DiscoveryRequest {
  readonly generationId: string
  readonly sourceId: string
  readonly file: File
  readonly signal?: AbortSignal
  readonly onProgress?: (phase: string, done: number, total: number) => void
}

export interface TextSourceDiscovery {
  readonly kind: 'text'
  readonly generationId: string
  readonly sourceId: string
  readonly fileName: string
  readonly byteLength: number
  readonly lineCount: number
  readonly identities: readonly CanonicalIdentity[]
  readonly detection: DetectionResult
  readonly lineEndings: Uint8Array
}

export interface PcapSourceDiscovery {
  readonly kind: 'pcap'
  readonly generationId: string
  readonly sourceId: string
  readonly fileName: string
  readonly byteLength: number
  readonly format: CaptureFormat
  readonly identities: readonly CanonicalIdentity[]
  readonly discovery: SourceDiscovery
  /** Payload-free container metadata returned by the processing worker. */
  readonly container: {
    readonly descriptors: readonly PacketRecordDescriptor[]
    readonly checkpoints: readonly SparseCheckpoint[]
    readonly issues: readonly ParseIssue[]
    readonly classicHeader?: ClassicPcapHeader
    readonly pcapngSections?: readonly PcapngSectionInfo[]
    readonly pcapngInterfaces?: readonly PcapngInterfaceInfo[]
    /** R10 — worker coverage rollup; `discovery.packetDiscovery` is empty on the packed path. */
    readonly coverageRollup?: WireCoverageRollup
  }
  readonly policy: SanitizationPolicy
}

export interface TestSourceDiscovery {
  readonly kind: 'test'
  readonly generationId: string
  readonly sourceId: string
  readonly fileName: string
  readonly byteLength: number
  readonly identities: readonly CanonicalIdentity[]
}

export type CorrelationSourceDiscovery =
  | TextSourceDiscovery
  | PcapSourceDiscovery
  | TestSourceDiscovery

export interface BuildPlanRequest {
  readonly generationId: string
  readonly sourceId: string
  readonly snapshot: MappingSnapshot
  readonly discovery: CorrelationSourceDiscovery
  readonly profileRevision?: number
}

export interface TextSourcePlan {
  readonly kind: 'text'
  readonly generationId: string
  readonly sourceId: string
  readonly mappingRevision: number
  readonly profileRevision: number
  readonly plan: ReplacementPlan
  readonly packed: PackedMatchIndex
  readonly matches: readonly ResolvedMatch[]
  readonly outputFileName: string
}

export interface PcapSourcePlan {
  readonly kind: 'pcap'
  readonly generationId: string
  readonly sourceId: string
  readonly mappingRevision: number
  readonly profileRevision: number
  readonly plan: PcapPlanSnapshot
  readonly outputFileName: string
}

export interface TestSourcePlan {
  readonly kind: 'test'
  readonly generationId: string
  readonly sourceId: string
  readonly mappingRevision: number
  readonly signature: string
  readonly outputFileName: string
}

export type CorrelationSourcePlan = TextSourcePlan | PcapSourcePlan | TestSourcePlan

export interface SourceAdapter<
  TDiscovery extends CorrelationSourceDiscovery = CorrelationSourceDiscovery,
  TPlan extends CorrelationSourcePlan = CorrelationSourcePlan,
> {
  readonly kind: AdapterKind
  probe(head: Uint8Array, file: File): ProbeResult
  preflight(file: File, limits: SourceLimits): Promise<SourcePreflightResult>
  discover(request: DiscoveryRequest): Promise<TDiscovery>
  buildPlan(request: BuildPlanRequest & { discovery: TDiscovery }): Promise<TPlan>
}

/** T73 — segment of an auto-split oversized input (shared mapping; merge on export). */
export interface SourceSplitMeta {
  readonly splitGroupId: string
  readonly splitIndex: number
  readonly splitCount: number
  readonly uniquePayloadStart: number
  readonly mergeOutputBaseName: string
  readonly format: 'text' | 'classic-pcap' | 'pcapng'
}

export interface StagedSourceDescriptor {
  readonly sourceId: string
  readonly kind: SourceKind
  readonly file: File
  readonly outputFileName?: string
  /** Paste/in-memory inputs use a lower aggregate cap (Stage 24). */
  readonly inputKind?: 'file' | 'paste'
  readonly split?: SourceSplitMeta
}

export type SourceLifecyclePhase =
  | 'staged'
  | 'discovering'
  | 'resolved'
  | 'planned'
  | 'failed'
  | 'cancelled'

export type SourceImportState = 'pending' | 'ok' | 'failed'
export type SourceCoverageState = 'pending' | 'ok' | 'partial'
export type SourceExportState = 'pending' | 'ready' | 'blocked'

/**
 * Persisted Inspector toggles for a text source in a mixed set.
 * Survives remount and drives export assessment (must match SessionModel).
 */
export interface CorrelationTextReviewState {
  readonly categoryMasters: Readonly<Record<string, boolean>>
  readonly entityEnabled: Readonly<Record<string, boolean>>
}

export interface CorrelationSourceRecord {
  readonly sourceId: string
  readonly kind: SourceKind
  readonly fileName: string
  readonly outputFileName: string
  readonly byteLength: number
  readonly inputKind: 'file' | 'paste'
  readonly phase: SourceLifecyclePhase
  readonly importState: SourceImportState
  readonly coverageState: SourceCoverageState
  readonly exportState: SourceExportState
  readonly file: File
  readonly discovery: CorrelationSourceDiscovery | null
  readonly plan: CorrelationSourcePlan | null
  /** Text Inspector toggles published into the correlation plan. */
  readonly textReview: CorrelationTextReviewState | null
  readonly errorCode: string | null
  readonly errorMessage: string | null
  /** T73 — when set, export merges this group into one file. */
  readonly split?: SourceSplitMeta
}

export type CorrelationSessionPhase = 'empty' | 'staged' | 'processing' | 'ready' | 'failed'

export interface CorrelationSessionView {
  readonly sessionId: string | null
  readonly generationId: string | null
  readonly phase: CorrelationSessionPhase
  readonly sourceCount: number
  readonly mappingRevision: number | null
  readonly sourceIds: readonly string[]
}

export type CorrelationErrorCode =
  | 'correlation-too-many-sources'
  | 'correlation-aggregate-too-large'
  | 'correlation-duplicate-source-id'
  | 'correlation-empty'
  | 'correlation-not-staged'
  | 'correlation-probe-failed'
  | 'correlation-preflight-failed'
  | 'correlation-discover-failed'
  | 'correlation-resolve-failed'
  | 'correlation-plan-failed'
  | 'correlation-cancelled'
  | 'correlation-adapter-missing'
  | 'correlation-not-ready'
  | 'correlation-source-missing'
  | 'correlation-staging-aborted'
  | 'correlation-stale-generation'
  | 'correlation-paste-aggregate-too-large'
  | 'correlation-profile-conflict'

export interface CorrelationError {
  readonly code: CorrelationErrorCode
  readonly message: string
  readonly sourceId?: string
}

export interface StageCorrelationResult {
  readonly ok: true
  readonly sessionId: string
  readonly sourceCount: number
  readonly totalBytes: number
}

export interface ProcessCorrelationResult {
  readonly ok: true
  readonly sessionId: string
  readonly mappingRevision: number
  readonly sourceCount: number
}

export interface AddCorrelationSourceResult {
  readonly ok: true
  readonly sourceId: string
  readonly mappingRevision: number
  readonly sourceCount: number
}

export interface RemoveCorrelationSourceResult {
  readonly ok: true
  readonly sourceId: string
  readonly mappingRevision: number
  readonly sourceCount: number
  readonly aliasRetained: true
}

export interface TextAdapterProfileContext {
  readonly profile: RulesetConfig
  readonly profileRevision: number
}

export interface PcapAdapterProfileContext {
  readonly profileRevision: number
}
