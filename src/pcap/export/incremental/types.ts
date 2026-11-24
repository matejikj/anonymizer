/**
 * Incremental PCAP export types and batch limits (Stage 11).
 */

export const PCAP_EXPORT_PROTOCOL_VERSION = 3

export interface ExportBatchLimits {
  readonly maxPackets: number
  readonly maxBytes: number
  readonly maxTimeMs: number
}

export const DEFAULT_EXPORT_BATCH_LIMITS: ExportBatchLimits = {
  maxPackets: 32,
  maxBytes: 512 * 1024,
  maxTimeMs: 16,
}

export type IncrementalExportPhase =
  | 'rewriting'
  | 'checksums'
  | 'assembling'
  | 'validating'
  | 'binding'
  | 'writing-recovery'

export interface IncrementalExportProgress {
  readonly phase: IncrementalExportPhase
  readonly packetsDone: number
  readonly packetsTotal: number
  readonly chunksEmitted: number
}

export interface IncrementalExportChunk {
  readonly index: number
  readonly buffer: ArrayBuffer
}
