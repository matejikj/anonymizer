/**
 * T04 — shared anonymization incident model (PCAP + text).
 * Never stores original identity values — only codes, categories, and counts.
 */

import { assertNever } from './assertNever.ts'
import { PCAP_KERNEL_BUDGETS } from './capabilityContract.ts'

export const INCIDENT_UNITS = ['field', 'payload', 'packet', 'line'] as const
export type IncidentUnit = (typeof INCIDENT_UNITS)[number]

export const INCIDENT_STAGES = [
  'discovery',
  'mapping',
  'plan',
  'reassembly',
  'export',
  'detection',
] as const
export type IncidentStage = (typeof INCIDENT_STAGES)[number]

export const INCIDENT_REASONS = [
  'mapping-canonicalize-failed',
  'mapping-alias-missing',
  'sanitizer-exception',
  'detector-exception',
  'patch-length-mismatch',
  'unknown',
] as const
export type IncidentReason = (typeof INCIDENT_REASONS)[number]

export const INCIDENT_FALLBACKS = [
  'field-masked',
  'payload-masked',
  'packet-masked',
  'packet-dropped',
  'line-masked',
] as const
export type IncidentFallback = (typeof INCIDENT_FALLBACKS)[number]

/** Default cap for retained incident records (additional failures only increment counters). */
export const DEFAULT_INCIDENT_LOG_CAPACITY = PCAP_KERNEL_BUDGETS.incidentLogMaxRecords

/** Default approximate byte budget for retained incident records. */
export const DEFAULT_INCIDENT_LOG_MAX_BYTES = PCAP_KERNEL_BUDGETS.incidentLogMaxBytes

/**
 * Structured fail-closed event. No field may carry an original/canonical value.
 */
export interface AnonymizationIncident {
  readonly unit: IncidentUnit
  readonly sourceId: string
  readonly packetIndex?: number
  /** 1-based Wireshark-style packet number. */
  readonly packetNumber?: number
  readonly lineNumber?: number
  /** Technical protocol id (sip, sdp, …) — never a payload snippet. */
  readonly protocol?: string
  /** Identity category code only — never the original/canonical value. */
  readonly category?: string
  readonly stage: IncidentStage
  readonly reason: IncidentReason
  readonly fallback: IncidentFallback
}

function estimateIncidentBytes(i: AnonymizationIncident): number {
  // Rough JSON footprint — codes/ids only; never values.
  return (
    96
    + (i.sourceId?.length ?? 0)
    + (i.protocol?.length ?? 0)
    + (i.category?.length ?? 0)
  )
}

export interface IncidentAggregateKey {
  readonly protocol: string
  readonly reason: IncidentReason
  readonly fallback: IncidentFallback
}

export interface IncidentAggregateCount extends IncidentAggregateKey {
  readonly count: number
}

export interface IncidentLogSnapshot {
  readonly incidents: readonly AnonymizationIncident[]
  readonly aggregates: readonly IncidentAggregateCount[]
  readonly truncated: boolean
  readonly totalFailures: number
}

function aggregateKey(i: AnonymizationIncident): string {
  return `${i.protocol ?? '*'}|${i.reason}|${i.fallback}`
}

function incidentDedupeKey(i: AnonymizationIncident): string {
  return [
    i.unit,
    i.sourceId,
    i.packetIndex ?? '',
    i.lineNumber ?? '',
    i.protocol ?? '',
    i.category ?? '',
    i.stage,
    i.reason,
    i.fallback,
  ].join('|')
}

/** Exhaustiveness helper for reason switches. */
export function assertIncidentReason(reason: IncidentReason): IncidentReason {
  switch (reason) {
    case 'mapping-canonicalize-failed':
    case 'mapping-alias-missing':
    case 'sanitizer-exception':
    case 'detector-exception':
    case 'patch-length-mismatch':
    case 'unknown':
      return reason
    default:
      return assertNever(reason)
  }
}

/**
 * Bounded incident log: count + byte caps; always updates aggregates.
 */
export class IncidentLog {
  private readonly capacity: number
  private readonly maxBytes: number
  private readonly records: AnonymizationIncident[] = []
  private readonly seen = new Set<string>()
  private readonly aggregateMap = new Map<string, IncidentAggregateCount>()
  private truncated = false
  private totalFailures = 0
  private retainedBytes = 0

  constructor(
    capacity = DEFAULT_INCIDENT_LOG_CAPACITY,
    maxBytes = DEFAULT_INCIDENT_LOG_MAX_BYTES,
  ) {
    this.capacity = Math.max(0, capacity)
    this.maxBytes = Math.max(0, maxBytes)
  }

  record(incident: AnonymizationIncident): void {
    assertIncidentReason(incident.reason)
    this.totalFailures += 1
    const aKey = aggregateKey(incident)
    const prev = this.aggregateMap.get(aKey)
    if (prev) {
      this.aggregateMap.set(aKey, { ...prev, count: prev.count + 1 })
    } else {
      this.aggregateMap.set(aKey, {
        protocol: incident.protocol ?? '*',
        reason: incident.reason,
        fallback: incident.fallback,
        count: 1,
      })
    }

    const dKey = incidentDedupeKey(incident)
    if (this.seen.has(dKey)) return
    this.seen.add(dKey)

    const need = estimateIncidentBytes(incident)
    if (
      this.records.length >= this.capacity
      || this.retainedBytes + need > this.maxBytes
    ) {
      this.truncated = true
      return
    }
    this.retainedBytes += need
    this.records.push(incident)
  }

  snapshot(): IncidentLogSnapshot {
    return {
      incidents: [...this.records],
      aggregates: [...this.aggregateMap.values()],
      truncated: this.truncated,
      totalFailures: this.totalFailures,
    }
  }

  get size(): number {
    return this.records.length
  }

  get isTruncated(): boolean {
    return this.truncated
  }
}

/** Wire-safe JSON shape (no values). */
export type WireAnonymizationIncident = AnonymizationIncident
export type WireIncidentLogSnapshot = IncidentLogSnapshot

export const EMPTY_INCIDENT_LOG_SNAPSHOT: IncidentLogSnapshot = {
  incidents: [],
  aggregates: [],
  truncated: false,
  totalFailures: 0,
}
