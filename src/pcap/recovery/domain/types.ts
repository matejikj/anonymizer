/**
 * PCAP recovery domain types — bound to two-level PCAP runtime, not text profiles.
 */

import type { PcapAnonymizationLevel } from '../../profile/pcapAnonymizationLevel'

/** Immutable plan identity required by recovery export/restore pairing. */
export interface PcapPlanIdentity {
  readonly generationId: string
  readonly pcapLevel: PcapAnonymizationLevel
  readonly policyHash: string
  readonly engineVersion: string
}

export type PcapRecoveryRestoreEncoding =
  | 'full-literal-frames-v1'
  | 'copy-anonymized-literal-v1'

export type PcapRecoveryLookupEncoding = 'compact-index-v1'

export type RecoveryLookupCategory =
  | 'ipv4'
  | 'ipv6'
  | 'mac'
  | 'vlan'
  | 'port'
  | 'hostname'
  | 'email'
  | 'url'
  | 'sip-user'
  | 'sip-phone'
  | 'sip-call-id'
  | 'sip-token'
  | 'rtp-ssrc'
  | 'radio-id'
  | 'sdp-session-id'
  | 'opaque-id'
  /** T45 — cross-format phone (new bundles); older sip-phone IDs remain valid. */
  | 'phone'
  /** T45 — cross-format user principal; older sip-user / other remain valid. */
  | 'user'
  /** T16 — mobile subscriber / equipment identities. */
  | 'imsi'
  | 'imei'
  /** T20 — SNMPv3 engine ID. */
  | 'snmp-engine-id'
  /** T26 — GTP TEID. */
  | 'teid'
  /** T25 — SS7/SIGTRAN point code. */
  | 'point-code'
  /** T40 — 802.11 / RADIUS SSID. */
  | 'ssid'
  | 'other'

export const RECOVERY_LOOKUP_CATEGORIES = [
  'ipv4',
  'ipv6',
  'mac',
  'vlan',
  'port',
  'hostname',
  'email',
  'url',
  'sip-user',
  'sip-phone',
  'sip-call-id',
  'sip-token',
  'rtp-ssrc',
  'radio-id',
  'sdp-session-id',
  'opaque-id',
  'phone',
  'user',
  'imsi',
  'imei',
  'snmp-engine-id',
  'teid',
  'point-code',
  'ssid',
  'other',
] as const satisfies readonly RecoveryLookupCategory[]

export type RecoveryMatchKind = 'exact' | 'ambiguous' | 'redacted'

/**
 * FINAL frame manifest fields (v2).
 * UI only receives bounded summaries after open, never the raw manifest bytes.
 */
export interface PcapRecoveryManifestV1 {
  readonly recoveryId: Uint8Array
  readonly originalFileName: string
  readonly originalFormat: 'pcap' | 'pcapng'
  readonly originalByteLength: bigint
  readonly originalSha256: Uint8Array
  readonly anonymizedByteLength: bigint
  readonly anonymizedSha256: Uint8Array
  readonly pcapLevel: PcapAnonymizationLevel
  readonly policyHash: Uint8Array
  readonly engineVersion: string
  readonly restoreEncoding: PcapRecoveryRestoreEncoding
  readonly lookupEncoding: PcapRecoveryLookupEncoding
  readonly dataFrameCount: number
  readonly indexFrameCount: number
  readonly lookupEntryCount: bigint
  readonly occurrenceCount: bigint
  readonly originalPacketCount: bigint
  readonly anonymizedPacketCount: bigint
  readonly indexSha256: Uint8Array
  readonly footerSha256: Uint8Array
}

/** Export-time recovery switch — never a third PCAP level or text-profile field. */
export interface RecoveryExportOptions {
  readonly enabled: boolean
  /**
   * Opt-in COPY_ANON DATA encoding. Default off — full-literal remains the
   * production path until a benchmark justifies enabling.
   */
  readonly copyAnon?: boolean
}

export const RECOVERY_EXPORT_DISABLED: RecoveryExportOptions = Object.freeze({
  enabled: false,
})

/** Safe UI summary after preflight (no secrets). */
export interface RecoveryPairSummary {
  readonly anonymizedPresent: boolean
  readonly recoveryPresent: boolean
  readonly formatVersion: number
  readonly schemaVersion: number
  readonly anonymizedHashPrefix64: string
  readonly pairLooksCompatible: boolean
}

/** Safe UI summary after unlock (no original values). */
export interface UnlockedRecoverySummary {
  readonly sessionId: string
  readonly generationId: string
  readonly pcapLevel: PcapAnonymizationLevel
  readonly policyHash: string
  readonly engineVersion: string
  readonly originalFormat: 'pcap' | 'pcapng'
  readonly originalByteLength: number
  readonly anonymizedByteLength: number
  readonly lookupEntryCount: number
  readonly originalPacketCount: number
  readonly anonymizedPacketCount: number
  readonly idleTimeoutMs: number
}

/** Step 7 — extracted query token (bounded). */
export type RecoveryQueryCandidate =
  | {
      readonly kind: 'value'
      readonly categoryHint: RecoveryLookupCategory | 'unknown'
      readonly text: string
      readonly start: number
      readonly end: number
    }
  | {
      readonly kind: 'packet'
      readonly anonymizedPacketNumber: number
      readonly start: number
      readonly end: number
    }

/** Step 7 — one search hit (may withhold original when ambiguous). */
export interface RecoveryHit {
  readonly hitId: string
  readonly status: 'exact' | 'ambiguous' | 'redacted' | 'packet-only'
  readonly category: RecoveryLookupCategory | 'unknown'
  readonly matchKind: RecoveryMatchKind | 'none'
  readonly queriedValue: string
  /** Present only when uniquely resolved (never for ambiguous without context). */
  readonly originalValue?: string
  readonly originalWire?: string
  readonly anonymizedCanonical?: string
  readonly anonymizedPacketNumber?: number
  readonly originalPacketNumber?: number
  readonly candidateCount: number
  readonly entryIndex?: number
  readonly occurrenceIndex?: number
}

export interface RecoveryResultPage {
  readonly hits: readonly RecoveryHit[]
  readonly totalHits: number
  readonly offset: number
  readonly limit: number
  readonly truncated: boolean
  readonly queryCandidateCount: number
  readonly nextOffset: number | null
}

/** Step 8 — reference passed from a search hit into packet restore. */
export interface RecoveryHitRef {
  readonly originalPacketNumber?: number
  readonly anonymizedPacketNumber?: number
  readonly entryIndex?: number
  readonly occurrenceIndex?: number
}

/** Step 8 — bounded packet view for UI (no full-file bytes). */
export interface RestoredPacketView {
  readonly originalPacketNumber: number
  readonly anonymizedPacketNumber: number | null
  readonly format: 'pcap' | 'pcapng'
  readonly linkType: number
  readonly capturedLength: number
  readonly originalLength: number
  /** Link-layer payload (not the full capture). */
  readonly originalPayload: ArrayBuffer
  /** Optional anonymized counterpart payload when extractable. */
  readonly anonymizedPayload?: ArrayBuffer
  /** Mini-capture is a derived valid file, not the full original. */
  readonly miniCaptureDerived: true
  readonly fileOffset: number
  readonly recordByteLength: number
}

/** Step 8 — verified restore summary (download only after verified === true). */
export interface RestoreSummary {
  readonly kind: 'mini-capture' | 'full'
  readonly fileName: string
  readonly byteLength: number
  readonly sha256Hex: string
  readonly verified: boolean
  readonly originalPacketNumber?: number
}

