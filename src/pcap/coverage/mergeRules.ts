/**
 * Deterministic overlap/merge rules for unified coverage (Stage 10).
 */

import type { UnifiedCoverageStatus, UnifiedLayerCoverage } from './types'

/** Higher index = higher priority; cannot be overridden by lower. */
const STATUS_PRIORITY: readonly UnifiedCoverageStatus[] = [
  'covered',
  'redacted',
  'truncated',
  'preserved-safe',
  'preserved-for-diagnostics',
  'heuristic',
  'preserved-unsafe',
  'encrypted',
  'requires-reassembly',
  'unsupported',
  'malformed',
  'processing-failed',
]

function statusPriority(status: UnifiedCoverageStatus): number {
  const idx = STATUS_PRIORITY.indexOf(status)
  return idx >= 0 ? idx : 0
}

export function dominantStatus(a: UnifiedCoverageStatus, b: UnifiedCoverageStatus): UnifiedCoverageStatus {
  return statusPriority(a) >= statusPriority(b) ? a : b
}

export function spansOverlap(a: UnifiedLayerCoverage, b: UnifiedLayerCoverage): boolean {
  if (a.packetIndex !== b.packetIndex) return false
  if (a.protocol !== b.protocol) return false
  const aEnd = a.offset + a.length
  const bEnd = b.offset + b.length
  return a.offset < bEnd && b.offset < aEnd
}

/** Merge overlapping spans — higher-priority status wins; issues unioned. */
export function mergeSpanPair(a: UnifiedLayerCoverage, b: UnifiedLayerCoverage): UnifiedLayerCoverage {
  const status = dominantStatus(a.status, b.status)
  const issues = [...new Set([...a.issues, ...b.issues])]
  const source = statusPriority(a.status) >= statusPriority(b.status) ? a.source : b.source
  const offset = Math.min(a.offset, b.offset)
  const end = Math.max(a.offset + a.length, b.offset + b.length)
  return {
    packetIndex: a.packetIndex,
    protocol: a.protocol,
    source,
    offset,
    length: end - offset,
    status,
    issues,
  }
}

export function mergePacketSpans(spans: readonly UnifiedLayerCoverage[]): UnifiedLayerCoverage[] {
  const out: UnifiedLayerCoverage[] = []
  for (const span of spans) {
    let merged = false
    for (let i = 0; i < out.length; i++) {
      const existing = out[i]!
      if (spansOverlap(existing, span)) {
        out[i] = mergeSpanPair(existing, span)
        merged = true
        break
      }
    }
    if (!merged) out.push(span)
  }
  return out
}

/** Heuristic sanitizer coverage is never treated as structural covered. */
export function effectiveAnonymizationStatus(spans: readonly UnifiedLayerCoverage[]): UnifiedCoverageStatus | null {
  let worst: UnifiedCoverageStatus | null = null
  for (const s of spans) {
    if (s.source === 'sanitizer' && s.status === 'heuristic') {
      worst = worst ? dominantStatus(worst, 'heuristic') : 'heuristic'
      continue
    }
    if (s.status === 'unsupported' || s.status === 'malformed' || s.status === 'requires-reassembly') {
      worst = worst ? dominantStatus(worst, s.status) : s.status
    }
  }
  return worst
}

export function isBlockingUnsupported(spans: readonly UnifiedLayerCoverage[]): boolean {
  return spans.some((s) => s.status === 'unsupported' && s.source === 'sanitizer')
}
