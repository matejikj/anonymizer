/**
 * Versioned PCAP recovery worker protocols.
 *
 * Export recovery options ride on the existing export worker request as an
 * optional field — absent / disabled must keep the anonymized-only hot path.
 * Restore uses a dedicated worker protocol (implemented in later steps).
 */

import type { PcapAnonymizationLevel } from '../../profile/pcapAnonymizationLevel'
import type { PcapPlanIdentity, RecoveryExportOptions } from '../domain/types'
import { PCAP_RECOVERY_ERROR } from '../domain/errors'

/** Bump only on incompatible restore/export recovery wire changes. */
export const PCAP_RECOVERY_PROTOCOL_VERSION = 1

export type RecoveryExportStreamId = 'anonymized' | 'recovery' | 'restore'

/**
 * Optional recovery payload on export `build-incremental` (and future dual-export).
 * When omitted or enabled !== true, workers must not create index seeds or
 * second sinks.
 */
export type WireRecoveryExportOptions = {
  enabled: boolean
  /**
   * Compact transferable index seed (step 4). Step 1 reserves the field only.
   * Opaque binary; must not be structured-cloned as JS object graphs.
   */
  indexSeed?: ArrayBuffer
  /** Opt-in COPY_ANON (step 9). Omitted / false → full-literal. */
  copyAnon?: boolean
}

export type WirePcapPlanIdentity = {
  generationId: string
  pcapLevel: PcapAnonymizationLevel
  policyHash: string
  engineVersion: string
}

export function wirePlanIdentity(identity: PcapPlanIdentity): WirePcapPlanIdentity {
  return {
    generationId: identity.generationId,
    pcapLevel: identity.pcapLevel,
    policyHash: identity.policyHash,
    engineVersion: identity.engineVersion,
  }
}

export function toWireRecoveryExportOptions(
  options: (RecoveryExportOptions & { indexSeed?: ArrayBuffer }) | undefined | null,
): WireRecoveryExportOptions | undefined {
  if (!options || options.enabled !== true) {
    return undefined
  }
  return {
    enabled: true,
    ...(options.indexSeed ? { indexSeed: options.indexSeed } : {}),
    ...(options.copyAnon === true ? { copyAnon: true } : {}),
  }
}

export const PCAP_RECOVERY_WORKER_ERROR = {
  ...PCAP_RECOVERY_ERROR,
  invalidVersion: 'invalid-recovery-protocol-version',
} as const

export function validateRecoveryProtocolVersion(version: number): string | null {
  if (version !== PCAP_RECOVERY_PROTOCOL_VERSION) {
    return PCAP_RECOVERY_WORKER_ERROR.invalidVersion
  }
  return null
}

/** Restore worker request surface (step 6+) — contract only in step 1. */
export type PcapRestoreWorkerRequest =
  | {
      type: 'preflight'
      protocolVersion: number
      requestId: string
      generationId: string
      anonymizedBlob: Blob
      recoveryBlob: Blob
    }
  | {
      type: 'unlock'
      protocolVersion: number
      requestId: string
      generationId: string
    }
  | {
      type: 'search'
      protocolVersion: number
      requestId: string
      generationId: string
      sessionId: string
      query: string
      offset?: number
      limit?: number
    }
  | {
      type: 'open-packet'
      protocolVersion: number
      requestId: string
      generationId: string
      sessionId: string
      hitRef: import('../domain/types').RecoveryHitRef
    }
  | {
      type: 'restore-packet'
      protocolVersion: number
      requestId: string
      generationId: string
      sessionId: string
      hitRef: import('../domain/types').RecoveryHitRef
    }
  | {
      type: 'restore-all'
      protocolVersion: number
      requestId: string
      generationId: string
      sessionId: string
    }
  | {
      type: 'lock'
      protocolVersion: number
      requestId: string
      generationId: string
      sessionId?: string
    }
  | {
      type: 'chunk-ack'
      protocolVersion: number
      requestId: string
      streamId: RecoveryExportStreamId
      chunkIndex: number
    }
  | {
      type: 'packet-map'
      protocolVersion: number
      requestId: string
      generationId: string
      sessionId: string
    }

export type PcapRestoreWorkerResponse =
  | {
      type: 'preflight-ok'
      requestId: string
      generationId: string
      summary: {
        anonymizedPresent: boolean
        recoveryPresent: boolean
        formatVersion: number
        schemaVersion: number
        anonymizedHashPrefix64: string
        pairLooksCompatible: boolean
      }
    }
  | {
      type: 'unlocked'
      requestId: string
      generationId: string
      sessionId: string
      summary: {
        pcapLevel: PcapAnonymizationLevel
        policyHash: string
        engineVersion: string
        originalFormat: 'pcap' | 'pcapng'
        originalByteLength: number
        anonymizedByteLength: number
        lookupEntryCount: number
        originalPacketCount: number
        anonymizedPacketCount: number
        idleTimeoutMs: number
      }
    }
  | {
      type: 'search-result'
      requestId: string
      generationId: string
      sessionId: string
      page: import('../domain/types').RecoveryResultPage
    }
  | {
      type: 'packet-opened'
      requestId: string
      generationId: string
      sessionId: string
      view: import('../domain/types').RestoredPacketView
    }
  | {
      type: 'restore-complete'
      requestId: string
      generationId: string
      sessionId: string
      summary: import('../domain/types').RestoreSummary
    }
  | {
      type: 'progress'
      requestId: string
      generationId: string
      sessionId?: string
      phase: string
      done: number
      total: number
    }
  | {
      type: 'chunk'
      requestId: string
      generationId: string
      sessionId: string
      streamId: RecoveryExportStreamId
      chunkIndex: number
      buffer: ArrayBuffer
    }
  | {
      type: 'locked'
      requestId: string
      generationId: string
    }
  | {
      type: 'packet-map-result'
      requestId: string
      generationId: string
      sessionId: string
      /** Index n (1-based anonymized packet number) -> original packet number, or -1 if dropped. */
      anonymizedToOriginal: number[]
    }
  | {
      type: 'error'
      requestId: string
      generationId: string
      sessionId?: string
      code: string
      message: string
    }
