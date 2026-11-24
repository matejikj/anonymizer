/**
 * Wire protocol for PCAP export worker — transferable buffers, no BigInt in JSON.
 */

import type { ChecksumDisposition } from '../checksums/types'
import type { WirePacketRecordDescriptor } from '../processing/containerWireAdapter'
import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel'
import type { WireRecoveryExportOptions } from '../recovery/worker/protocol'
import { PCAP_EXPORT_PROTOCOL_VERSION } from './incremental/types'

export { PCAP_EXPORT_PROTOCOL_VERSION }
export type { WireRecoveryExportOptions }

export type WireTimestamp = {
  ticks: string
  unitsPerSecond: string
  offsetSeconds: string
}

export type WireBytePatch = {
  offset: number
  /** Transferred separately when posting from client. */
  data: ArrayBuffer
}

/**
 * A patch's byte range within the plan-level `patchData` buffer (see `WirePlanSnapshot`).
 * Real captures can carry millions of patches; giving each its own ArrayBuffer made the
 * postMessage() transfer list itself the bottleneck (each entry has real per-item transfer
 * overhead) — one shared buffer sliced by (byteOffset, length) transfers just as fast as a
 * handful of bytes moved once, regardless of patch count.
 */
export type WirePackedPatch = {
  offset: number
  byteOffset: number
  length: number
}

export type WirePlanChangeCounts = {
  mapped: number
  redacted: number
  'masked-content': number
  'preserved-encrypted': number
  'preserved-for-diagnostics': number
  'user-requested-drop': number
  blocked: number
}

export type WirePlanPacket = {
  index: number
  packetNumber: number
  drop: boolean
  patches: WirePackedPatch[]
  truncatedLength?: number
  originalCapturedLength: number
  originalLength: number
  linkType: number
  interfaceId: number
  sectionIndex: number
  originalTimestamp: WireTimestamp
  /** Step 8 — optional for older workers. */
  dispositionReason?: 'exported' | 'user-requested-drop' | 'blocked'
  changeCounts?: WirePlanChangeCounts
  maskedByteCount?: number
  primaryProtocol?: string
}

export type WireClassicHeader = {
  format: number
  endian: number
  timestampResolution: number
  versionMajor: number
  versionMinor: number
  snapLen: number
  linkType: number
  tzOffset: number
  sigfigs: number
}

export type WirePlanSnapshot = {
  generationId: string
  /** Active PCAP anonymization level — required for recovery plan identity. */
  pcapLevel?: PcapAnonymizationLevel
  /** @deprecated Prefer pcapLevel — retained for older workers. */
  profileId: string
  /**
   * Built-in policy integrity hash.
   * Recovery canonical name is policyHash; value is identical.
   */
  profileHash: string
  /** Alias of profileHash for recovery / plan identity (optional for older workers). */
  policyHash?: string
  format: number
  fileName: string
  engineVersion: string
  packets: WirePlanPacket[]
  /** Concatenated bytes for every patch in `packets[].patches`, sliced by (byteOffset, length). */
  patchData: ArrayBuffer
  /** R10 — packets with patches and/or truncation (optional for older workers). */
  packetsWithChanges?: number
  droppedPacketNumbers: number[]
  classicHeader?: WireClassicHeader
  // PCAPNG section/interface metadata is JSON-serializable (no BigInt)
  pcapngSections?: ReadonlyArray<Record<string, unknown>>
  pcapngInterfaces?: ReadonlyArray<Record<string, unknown>>
  /** CF-12 — optional for older workers; default relative-exact */
  timestamps?: 'relative' | 'relative-bucketed' | 'enumerated'
  /** Step 7 — opaque timestamp anchor seed; never placed in plaintext reports. */
  timestampAnchorSeed?: string
  /** Step 8 — optional aggregates for older workers. */
  changeCategoryTotals?: WirePlanChangeCounts
  maskedByteCount?: number
  dropsByReason?: Partial<Record<'exported' | 'user-requested-drop' | 'blocked', number>>
  dropsByProtocol?: Record<string, number>
  /** T04 — value-free incident log snapshot (optional for older workers). */
  incidents?: import('../../domain/anonymizationIncident').IncidentLogSnapshot
  /** T62 — disposition ledger aggregates only (optional for older workers). */
  dispositionLedger?: import('./dispositionLedger').DispositionLedgerAggregate
  /** T65 — leak remediation summary (optional for older workers). */
  leakRemediation?: {
    readonly passes: number
    readonly autoRemediated: {
      readonly occurrences: number
      readonly packets: number
      readonly byCategory: Readonly<Partial<Record<string, number>>>
      readonly passes: number
      readonly escalatedPackets: number
    }
    readonly residualLeakHits: number
  }
}

export type WirePacketEnvelope = {
  packetNumber: number
  timestamp: WireTimestamp
  capturedLength: number
  originalLength: number
  linkType: number
  interfaceId: number
  sectionIndex: number
  fileOffset: number
  data: ArrayBuffer
}

export type WireParseIssue = {
  severity: number
  code: string
  message: string
  packetNumber?: number
  fileOffset?: number
}

export type WireExportBuildResult = {
  fileName: string
  changedPackets: number
  truncatedPayloads: number
  validationValid: boolean
  validationIssueCount: number
  validationNewBlockingCount?: number
  checksumCounts: Record<ChecksumDisposition, number>
  /** Step 3 — set when recovery sidecar stream completed. */
  recoveryCreated?: boolean
  recoveryChunkCount?: number
  anonymizedByteLength?: number
  /** Hex of anonymized SHA-256 (safe to surface for pairing checks; not a secret). */
  anonymizedSha256Hex?: string
}

export type PcapExportProgressPhase =
  | 'rewriting'
  | 'checksums'
  | 'assembling'
  | 'validating'
  | 'binding'
  | 'writing-recovery'

export type PcapExportStreamId = 'anonymized' | 'recovery'

export type PcapExportWorkerRequest =
  | {
      /** Incremental export from plan + descriptors + source blob. */
      type: 'build-incremental'
      protocolVersion: number
      requestId: string
      plan: WirePlanSnapshot
      descriptors: WirePacketRecordDescriptor[]
      sourceBlob: Blob
      expectedGenerationId?: string
      /** @deprecated Prefer expectedPolicyHash — same value. */
      expectedProfileHash?: string
      /** Plan policy hash guard (recovery / two-level identity). */
      expectedPolicyHash?: string
      batchLimits?: { maxPackets?: number; maxBytes?: number; maxTimeMs?: number }
      baselineIssues?: WireParseIssue[]
      /**
       * Optional recovery sidecar for this export only.
       * Absent or enabled !== true → anonymized-only hot path (unchanged).
       */
      recovery?: WireRecoveryExportOptions
    }
  | { type: 'cancel'; protocolVersion: number; requestId: string }
  | {
      type: 'chunk-ack'
      protocolVersion: number
      requestId: string
      chunkIndex: number
      /** Dual-stream ACK (step 3+); omitted on anonymized-only path. */
      streamId?: 'anonymized' | 'recovery'
    }

export type PcapExportWorkerResponse =
  | {
      type: 'progress'
      requestId: string
      phase: PcapExportProgressPhase
      packetsDone: number
      packetsTotal: number
      chunksEmitted?: number
      streamId?: PcapExportStreamId
      bytesDone?: number
      bytesTotal?: number
    }
  | {
      /** One emitted output chunk (transferable). */
      type: 'chunk'
      requestId: string
      chunkIndex: number
      buffer: ArrayBuffer
      /** Defaults to anonymized when omitted (recovery-off path). */
      streamId?: PcapExportStreamId
    }
  | {
      type: 'built-incremental'
      requestId: string
      chunkCount: number
      result: WireExportBuildResult
    }
  | { type: 'error'; requestId: string; code: string; message: string }

export const PCAP_EXPORT_WORKER_ERROR = {
  cancelled: 'cancelled',
  internal: 'internal',
  planRejected: 'plan-rejected',
  invalidVersion: 'invalid-protocol-version',
  recoveryFailed: 'recovery-failed',
} as const

export function validateExportProtocolVersion(version: number): string | null {
  if (version !== PCAP_EXPORT_PROTOCOL_VERSION) {
    return PCAP_EXPORT_WORKER_ERROR.invalidVersion
  }
  return null
}
