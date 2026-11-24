/**
 * Typed Worker protocol — ARCHITECTURE §8.
 * Manual postMessage; no Comlink.
 */

import type { EntitySummary } from '../domain/types.ts'
import type { RulesetConfig } from '../domain/configSchema.ts'
import { WorkerIssueCode } from '../domain/issueCodes.ts'
import type { PackedMatchBuffers } from '../engine/packedMatchIndex.ts'

/** T07 — `detected` may carry value-free IncidentLogSnapshot for line isolation. */
export const DETECTION_PROTOCOL_VERSION = 2
export const EXPORT_PROTOCOL_VERSION = 1

export type RequestId = string

export type { PackedMatchBuffers }

/** Compact replacement-plan buffers transferable to the main thread. */
export interface ReplacementPlanBuffers {
  lengthDeltas: ArrayBuffer
  fenwick: ArrayBuffer
  /** Parallel to matches: 1 = has replacement string index, 0 = disabled */
  enabledFlags: ArrayBuffer
  count: number
}

export interface PackedMatchWindow {
  starts: ArrayBuffer
  lengths: ArrayBuffer
  entityIndexes: ArrayBuffer
  flags: ArrayBuffer
  count: number
  /** Absolute original offset of this window's first character. */
  originalFrom: number
}

export interface PackedLineEndingWindow {
  /** 0=LF, 1=CRLF, 2=CR, 3=none (last line) — one byte per line in window */
  endings: ArrayBuffer
  lineCount: number
}

export interface ReplacementSnapshot {
  replacements: string[]
  entityEnabled: ArrayBuffer
}

export type DetectionWorkerRequest =
  | {
      type: 'start-detection'
      protocolVersion: number
      requestId: RequestId
      profile: RulesetConfig
    }
  | {
      type: 'input-chunk'
      protocolVersion: number
      requestId: RequestId
      sequence: number
      bytes?: ArrayBuffer
      byteOffset?: number
      byteLength?: number
      text?: string
      final: boolean
    }
  | { type: 'cancel'; protocolVersion: number; requestId: RequestId }
  | { type: 'build-plan'; protocolVersion: number; requestId: RequestId; entityBitset: ArrayBuffer }
  | {
      type: 'sync-replacements'
      protocolVersion: number
      requestId: RequestId
      /** entity key → replacement alias from MappingAuthority */
      replacements: Record<string, string>
    }

export type DetectionWorkerResponse =
  | { type: 'chunk-accepted'; requestId: RequestId; sequence: number }
  | {
      type: 'progress'
      requestId: RequestId
      processedBytes: number
      processedLines: number
    }
  | { type: 'rule-started'; requestId: RequestId; ruleId: string }
  | { type: 'heartbeat'; requestId: RequestId; ruleId?: string }
  | {
      type: 'detected'
      requestId: RequestId
      packedMatches: PackedMatchBuffers
      entities: EntitySummary[]
      lineCount: number
      /** T07 — line-isolation incidents (no original values). */
      incidents?: import('../domain/anonymizationIncident').IncidentLogSnapshot
    }
  | {
      type: 'plan-built'
      requestId: RequestId
      planBuffers: ReplacementPlanBuffers
    }
  | { type: 'replacements-synced'; requestId: RequestId }
  | {
      type: 'error'
      requestId: RequestId
      code: string
      ruleId?: string
      message: string
    }

export type ExportWorkerRequest =
  | {
      type: 'start-export'
      protocolVersion: number
      requestId: RequestId
      replacementSnapshot: ReplacementSnapshot
    }
  | {
      type: 'export-chunk'
      protocolVersion: number
      requestId: RequestId
      sequence: number
      text: string
      matchWindow: PackedMatchWindow
      /** Parallel to matchWindow.count; empty string = keep original span */
      windowReplacements: string[]
      lineEndings: PackedLineEndingWindow
      final: boolean
    }
  | { type: 'cancel'; protocolVersion: number; requestId: RequestId }

export type ExportWorkerResponse =
  | {
      type: 'chunk-exported'
      requestId: RequestId
      sequence: number
      utf8: ArrayBuffer
    }
  | { type: 'export-complete'; requestId: RequestId; byteLength: number }
  | { type: 'error'; requestId: RequestId; code: string; message: string }

/** Error codes used by workers / client. */
export const WORKER_ERROR = {
  cancelled: WorkerIssueCode.Cancelled,
  regexTimeout: WorkerIssueCode.RegexTimeout,
  invalidChunk: WorkerIssueCode.InvalidChunk,
  internal: WorkerIssueCode.Internal,
  lineLimit: WorkerIssueCode.LineLimit,
  invalidVersion: WorkerIssueCode.InvalidProtocolVersion,
} as const

export function validateDetectionProtocolVersion(version: number): string | null {
  if (version !== DETECTION_PROTOCOL_VERSION) {
    return WORKER_ERROR.invalidVersion
  }
  return null
}

export function validateExportProtocolVersion(version: number): string | null {
  if (version !== EXPORT_PROTOCOL_VERSION) {
    return WORKER_ERROR.invalidVersion
  }
  return null
}
