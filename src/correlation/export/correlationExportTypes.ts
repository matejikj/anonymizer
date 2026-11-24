/**
 * Multi-source correlation export contracts (Stage 29 / MIXED step 3).
 */

import type { SourceKind } from '../../domain/sourceArtifact'

/**
 * Per-source export readiness (T08).
 * `gaps` = fail-closed incomplete analysis (AI_READY_WITH_GAPS); still exportable.
 */
export type CorrelationExportSecurity = 'ready' | 'gaps' | 'exposed' | 'blocked'

export type CorrelationExportScope = 'set' | 'current'

export type CorrelationExportSkipReason =
  | 'not-planned'
  | 'failed'
  | 'blocked'
  | 'pending'
  | 'rebuilding'
  | null

export type CorrelationExportArtifactKind = 'data' | 'manifest'

export interface CorrelationExportFileItem {
  readonly sourceId: string
  readonly inputFileName: string
  readonly outputFileName: string
  readonly kind: SourceKind
  readonly security: CorrelationExportSecurity
  readonly exportable: boolean
  readonly exposedHint: string | null
  readonly skipReason: CorrelationExportSkipReason
  readonly skipDetail: string | null
  readonly artifactKind: CorrelationExportArtifactKind
}

export interface CorrelationExportPreview {
  readonly scope: CorrelationExportScope
  readonly files: readonly CorrelationExportFileItem[]
  readonly exportableCount: number
  readonly blockedCount: number
  readonly skippedCount: number
  readonly exposedCount: number
  readonly includeManifest: boolean
  readonly manifestFileName: string
  readonly canExportAll: boolean
  readonly partialOnly: boolean
  /** Data files that would be written (excludes companion manifest). */
  readonly dataFileCount: number
  /** Companion reports (e.g. shareable manifest). */
  readonly companionFileCount: number
  readonly generationId: string | null
  readonly mappingRevision: number | null
  readonly sourceIds: readonly string[]
  readonly canChooseCurrent: boolean
}

export type CorrelationExportJobPhase =
  | 'idle'
  | 'picking-directory'
  | 'exporting'
  | 'done'
  | 'cancelled'
  | 'error'

export interface CorrelationExportProgress {
  readonly phase: CorrelationExportJobPhase
  readonly fileIndex: number
  readonly fileTotal: number
  readonly currentFileName: string
  readonly currentMessage: string
  readonly completedFiles: readonly string[]
  readonly remainingFiles: readonly string[]
  readonly usedDirectoryPicker: boolean
  readonly usedMultiDownloadFallback: boolean
  /** True when browser downloads were triggered but disk write was not verified. */
  readonly downloadUnverified: boolean
}

export interface CorrelationExportResult {
  readonly ok: true
  readonly exportedFiles: readonly string[]
  readonly dataFiles: readonly string[]
  readonly companionFiles: readonly string[]
  readonly skippedFiles: readonly CorrelationExportFileItem[]
  readonly manifestExported: boolean
  readonly partial: boolean
  readonly exposedIncluded: boolean
  readonly usedDirectoryPicker: boolean
  readonly usedMultiDownloadFallback: boolean
  readonly downloadUnverified: boolean
}

export interface CorrelationExportFailure {
  readonly ok: false
  readonly code: 'cancelled' | 'empty' | 'blocked' | 'export-failed' | 'stale' | 'unstable'
  readonly message: string
  readonly completedFiles: readonly string[]
  readonly remainingFiles: readonly string[]
}

export type CorrelationExportOutcome = CorrelationExportResult | CorrelationExportFailure

export interface CorrelationCompletionSkipped {
  readonly inputFileName: string
  readonly outputFileName: string
  readonly reason: string
}

export interface CorrelationCompletionState {
  readonly exportedFiles: readonly string[]
  readonly dataFiles: readonly string[]
  readonly companionFiles: readonly string[]
  readonly skippedFiles: readonly CorrelationCompletionSkipped[]
  readonly manifestExported: boolean
  readonly partial: boolean
  readonly exposedIncluded: boolean
  /** Only true when full set succeeded with AI_READY (no gaps, no exposed). */
  readonly shareableWithAi: boolean
  /**
   * T08 three-state gate badge (not a third profile).
   * AI_READY iff shareableWithAi; worst-of sources otherwise.
   */
  readonly gateBadge: 'AI_READY' | 'AI_READY_WITH_GAPS' | 'NOT_AI_READY'
  readonly usedDirectoryPicker: boolean
  readonly downloadUnverified: boolean
}
