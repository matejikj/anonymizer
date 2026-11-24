/**
 * Bridge for single- or dual-sink PCAP export.
 * Kept in pcap/export so the anonymized hot path can accept a dual sink without
 * importing recovery/export modules.
 */

export interface ExportFinalizeResult {
  readonly blob?: Blob
  readonly fileName: string
  readonly byteLength: number
}

export interface DualSinkFinalizeResult {
  readonly anonymized: ExportFinalizeResult
  readonly recovery?: ExportFinalizeResult
  /** True only when recovery sink finalized successfully as part of a complete pair. */
  readonly recoveryCreated: boolean
}

/**
 * Owns sink lifecycle for anonymized (+ optional recovery) streams.
 * Error/cancel must abort all attached sinks and never report recoveryCreated.
 */
export interface DualSinkExportBridge {
  readonly partialFilePossible: boolean
  cancel(): void
  isActive(generationId?: string): boolean
  writeAnonymized(chunk: ArrayBuffer, generationId: string): Promise<boolean>
  writeRecovery?(chunk: ArrayBuffer, generationId: string): Promise<boolean>
  abort(): Promise<void>
  finalize(): Promise<DualSinkFinalizeResult>
}
