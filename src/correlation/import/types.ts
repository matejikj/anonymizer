/**
 * Multi-source import and staging types (Stage 27 / T05).
 */

import type { SourceKind } from '../../domain/sourceArtifact'
import type { CompressedFormat, InflateFormat } from './decompressInput.ts'
import type { InputRejection } from './inputRejection.ts'

export type StagingItemStatus = 'ready' | 'error' | 'duplicate-warning'

/** Present when a ready File was inflated from a compressed stream (T05/T72). */
export interface GzipInflationNote {
  readonly format: InflateFormat
  readonly compressedBytes: number
  readonly inflatedBytes: number
}

export interface StagingItemReady {
  readonly id: string
  readonly file: File
  readonly fileName: string
  readonly byteLength: number
  readonly status: 'ready'
  readonly kind: SourceKind
  readonly profileLabel: string
  /** Present when the ready File was inflated from `.gz` (original name kept for display). */
  readonly gzipInflation?: GzipInflationNote
  /** Display name of the dropped archive when different from `file.name`. */
  readonly sourceFileName?: string
}

export interface StagingItemError {
  readonly id: string
  readonly file: File
  readonly fileName: string
  readonly byteLength: number
  readonly status: 'error'
  readonly code: string
  readonly message: string
  readonly recoveryAction: 'remove' | 'retry'
  readonly rejection?: InputRejection
}

export interface StagingItemDuplicate {
  readonly id: string
  readonly file: File
  readonly fileName: string
  readonly byteLength: number
  readonly status: 'duplicate-warning'
  readonly kind: SourceKind
  readonly profileLabel: string
  readonly duplicateOfId: string
  readonly duplicateOfName: string
  readonly gzipInflation?: GzipInflationNote
  readonly sourceFileName?: string
}

export type StagingItem = StagingItemReady | StagingItemError | StagingItemDuplicate

export interface StagingBatchSummary {
  readonly fileCount: number
  readonly totalBytes: number
  readonly readyCount: number
  readonly errorCount: number
  readonly duplicateCount: number
  readonly aggregateLimitBytes: number
  readonly aggregateOverLimit: boolean
  readonly bytesToRemove: number | null
  readonly largestReadyIds: readonly string[]
}

export type ImportRoute =
  | { readonly kind: 'nothing' }
  | { readonly kind: 'single-text'; readonly file: File }
  | { readonly kind: 'single-pcap'; readonly file: File }
  | { readonly kind: 'staging'; readonly summary: StagingBatchSummary }

export type DetectedSourceKind = SourceKind | 'unsupported' | 'compressed'

export type SourceProbeResult =
  | { readonly kind: SourceKind }
  | {
      readonly kind: 'unsupported'
      readonly code: string
      readonly message?: string
    }
  | {
      readonly kind: 'compressed'
      readonly format: CompressedFormat
    }
