/**
 * PCAP processing worker wire protocol (Stage 8 / Stage 16 typed wire DTOs).
 */

import type { CaptureFormat } from '../domain/types'
import type { SanitizationPolicy } from '../sanitize/types'
import type { WireMappingSnapshot, WireRepresentationConstraintWire } from '../../mapping/protocol'
import type { WirePlanSnapshot, WireClassicHeader } from '../export/workerProtocol'
import type { WireContainerMetadata } from './containerWireAdapter'
import type { PcapProfile } from '../profile/schema'

/** T04 — plan wire; R10 packed discover; 8 — protocol/family counts in coverage rollup. */
export const PCAP_PROCESSING_PROTOCOL_VERSION = 9

/** Wire-safe closure failure — category/reason/packet only (never canonical/value). */
export interface WireClosureFailure {
  readonly packetIndex: number
  readonly category: string
  readonly reason: 'missing-snapshot-entry' | 'missing-constraint-alias'
}

export type ProcessingRequestId = string

export interface WireCoverageEntry {
  protocolId: string
  packetCount: number
  unsupportedCount: number
  issues: string[]
}

export interface WireEntityEntry {
  key: string
  category: string
  value: string
  firstPacket: number
  count: number
}

export interface WirePacketSummary {
  packetNumber: number
  protocols: string[]
  issues: string[]
  hasUnsupported: boolean
}

export interface WireEntityReplacementIntent {
  kind: 'entity-replacement'
  packetIndex: number
  offset: number
  byteLength: number
  category: string
  canonical: string
  constraint: WireRepresentationConstraintWire
  /** Original wire spelling for length-aware alias allocation (step 2). */
  originalSpelling?: string
}

export interface WireSourceDiscoveryPayload {
  generationId: string
  sourceId: string
  totalPackets: number
  decodedPackets: number
  entityCount: number
  intentCount: number
  entityOverflow: boolean
  coverage: WireCoverageEntry[]
  entities: WireEntityEntry[]
  summaries: WirePacketSummary[]
  /** Entity-replacement intents only (compact). */
  intents: WireEntityReplacementIntent[]
  /** Exact entity → packet index lists (Stage 10). */
  entityOccurrences?: Array<{ entityKey: string; packetIndices: readonly number[] }>
  /** T06 — content-derived port roles (`udp/5070` → sip). */
  portFlowHints?: Array<{ canonical: string; flow: string }>
}

export type WirePcapProfilePayload = PcapProfile

export type PcapProcessingWorkerRequest =
  | {
      type: 'process'
      protocolVersion: number
      requestId: ProcessingRequestId
      generationId: string
      sourceId: string
      format: CaptureFormat
      policy: SanitizationPolicy
      blob: Blob
      batchSize?: number
    }
  | {
      type: 'build-plan'
      protocolVersion: number
      requestId: ProcessingRequestId
      generationId: string
      profile: WirePcapProfilePayload
      format: CaptureFormat
      fileName: string
      snapshot: WireMappingSnapshot
      classicHeader?: WireClassicHeader
      pcapngSections?: WirePlanSnapshot['pcapngSections']
      pcapngInterfaces?: WirePlanSnapshot['pcapngInterfaces']
      /** T04 — soft-fail closure residuals for incident recording (no identity values). */
      unresolvedClosureFailures?: readonly WireClosureFailure[]
    }
  | {
      type: 'cancel'
      protocolVersion: number
      requestId: ProcessingRequestId
      generationId: string
    }

export type PcapProcessingWorkerResponse =
  | {
      type: 'progress'
      requestId: ProcessingRequestId
      generationId: string
      phase: 'parsing' | 'analyzing' | 'discovering' | 'plan-build'
      packetsDone: number
      packetsTotal: number
    }
  | {
      type: 'discovered'
      requestId: ProcessingRequestId
      generationId: string
      discovery: WireSourceDiscoveryPayload
      container: WireContainerMetadata
    }
  | {
      type: 'plan-built'
      requestId: ProcessingRequestId
      generationId: string
      plan: WirePlanSnapshot
    }
  | {
      type: 'error'
      requestId: ProcessingRequestId
      generationId?: string
      code: string
      message: string
    }

export const PCAP_PROCESSING_WORKER_ERROR = {
  cancelled: 'cancelled',
  invalidVersion: 'invalid-protocol-version',
  invalidMessage: 'invalid-message',
  parseFailed: 'parse-failed',
  staleGeneration: 'stale-generation',
  internal: 'internal',
} as const

export function validateProcessingProtocolVersion(version: number): string | null {
  if (version !== PCAP_PROCESSING_PROTOCOL_VERSION) {
    return PCAP_PROCESSING_WORKER_ERROR.invalidVersion
  }
  return null
}
