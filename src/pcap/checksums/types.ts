/**
 * Checksum classification and aggregate counters for export report.
 * Enterprise step 6 adds originalState sidecard (VALID / INVALID / OFFLOADED_PARTIAL / …).
 */

import type { OriginalChecksumState } from './originalState'

export type { OriginalChecksumState } from './originalState'
export {
  ORIGINAL_CHECKSUM_STATES,
  isOriginalChecksumState,
  classifyOriginalChecksumState,
} from './originalState'

export type ChecksumDisposition =
  | 'recomputed'
  | 'incrementally-updated'
  | 'preserved-zero'
  | 'input-invalid'
  | 'offload-suspected'
  | 'not-verifiable'
  | 'unchanged'

export type ChecksumLayer = 'ipv4' | 'tcp' | 'udp' | 'sctp' | 'icmpv4' | 'icmpv6' | 'icmp-embedded-ipv4' | 'vrrp' | 'cdp'

export interface ChecksumFieldResult {
  readonly layer: ChecksumLayer
  readonly offset: number
  readonly disposition: ChecksumDisposition
  readonly inputValue: number
  readonly outputValue: number
  /** Pre-sanitize classification — never rewritten away silently. */
  readonly originalState: OriginalChecksumState
}

export interface ChecksumReport {
  readonly fields: readonly ChecksumFieldResult[]
  readonly counts: Readonly<Record<ChecksumDisposition, number>>
  /** Aggregate of originalState across fields (step 6 sidecard). Optional for legacy fixtures. */
  readonly originalStateCounts?: Readonly<Record<OriginalChecksumState, number>>
}

export function emptyChecksumCounts(): Record<ChecksumDisposition, number> {
  return {
    recomputed: 0,
    'incrementally-updated': 0,
    'preserved-zero': 0,
    'input-invalid': 0,
    'offload-suspected': 0,
    'not-verifiable': 0,
    unchanged: 0,
  }
}

export function emptyOriginalStateCounts(): Record<OriginalChecksumState, number> {
  return {
    VALID: 0,
    INVALID: 0,
    OFFLOADED_PARTIAL: 0,
    NOT_PRESENT: 0,
    NOT_VERIFIABLE_TRUNCATED: 0,
  }
}

export function aggregateChecksumReports(reports: ChecksumReport[]): ChecksumReport {
  const counts = emptyChecksumCounts()
  const originalStateCounts = emptyOriginalStateCounts()
  const fields: ChecksumFieldResult[] = []
  for (const r of reports) {
    fields.push(...r.fields)
    for (const [k, v] of Object.entries(r.counts)) {
      counts[k as ChecksumDisposition] += v
    }
    for (const [k, v] of Object.entries(r.originalStateCounts ?? emptyOriginalStateCounts())) {
      originalStateCounts[k as OriginalChecksumState] += v
    }
  }
  return { fields, counts, originalStateCounts }
}
