/**
 * T63 — coverage status must match what patches actually did.
 *
 * After `resolveDeferred()`, every `redacted` span must be fully covered by patches.
 * Violations record a value-free `status-mismatch` incident and residual-mask the span
 * (fail-closed). Optional `assert` mode throws for unit/conformance harnesses.
 */

import type { IncidentLog } from '../../domain/anonymizationIncident.ts'
import { createProtocolNeutralMaskFill } from './maskFill.ts'
import type { PatchCollector } from './PatchCollector.ts'
import type { BytePatch, LayerCoverage } from './types.ts'

export class StatusMismatchError extends Error {
  readonly packetIndex: number
  readonly protocol: string
  readonly spanCount: number

  constructor(packetIndex: number, protocol: string, spanCount: number) {
    super(
      `Coverage status mismatch (packetIndex=${packetIndex}, protocol=${protocol}, spans=${spanCount})`,
    )
    this.name = 'StatusMismatchError'
    this.packetIndex = packetIndex
    this.protocol = protocol
    this.spanCount = spanCount
  }
}

export interface StatusInvariantInput {
  readonly collector: PatchCollector
  readonly coverage: LayerCoverage[]
  readonly packetIndex: number
  readonly incidentLog?: IncidentLog
  readonly sourceId?: string
  readonly packetNumber?: number
  /**
   * When true, throw StatusMismatchError after remediating (conformance / unit tests).
   * Engine production path leaves this false — catch-all isolation must not swallow it.
   */
  readonly assert?: boolean
}

export interface StatusInvariantResult {
  readonly remediatedSpans: number
}

/** True when every byte in [start, start+length) is covered by at least one patch. */
export function isSpanFullyPatched(
  patches: readonly BytePatch[],
  start: number,
  length: number,
): boolean {
  if (length <= 0) return true
  const end = start + length
  const overlaps: Array<{ a: number; b: number }> = []
  for (const p of patches) {
    const pEnd = p.offset + p.data.length
    if (pEnd <= start || p.offset >= end) continue
    overlaps.push({ a: Math.max(start, p.offset), b: Math.min(end, pEnd) })
  }
  if (overlaps.length === 0) return false
  overlaps.sort((x, y) => x.a - y.a || x.b - y.b)
  let cursor = start
  for (const seg of overlaps) {
    if (seg.a > cursor) return false
    if (seg.b > cursor) cursor = seg.b
    if (cursor >= end) return true
  }
  return cursor >= end
}

/**
 * Enforce redacted-span patch coverage. Mutates collector (residual mask) and may
 * append `status-mismatch` to `coverage` issues via the returned count.
 */
export function enforceCoverageStatusInvariant(input: StatusInvariantInput): StatusInvariantResult {
  const {
    collector,
    coverage,
    packetIndex,
    incidentLog,
    sourceId = 'pcap',
    packetNumber,
    assert = false,
  } = input

  let remediatedSpans = 0
  let firstProtocol = 'unknown'

  for (const span of coverage) {
    if (span.status !== 'redacted' || span.length <= 0) continue
    const patches = collector.getPatches()
    if (isSpanFullyPatched(patches, span.offset, span.length)) continue

    if (remediatedSpans === 0) firstProtocol = span.protocol
    remediatedSpans += 1

    incidentLog?.record({
      unit: 'payload',
      sourceId,
      packetIndex,
      packetNumber,
      protocol: span.protocol,
      stage: 'plan',
      reason: 'status-mismatch',
      fallback: 'payload-masked',
    })

    const fill = createProtocolNeutralMaskFill({
      length: span.length,
      packetIndex,
      offset: span.offset,
      domain: `status-mismatch:${span.protocol}`,
    })
    collector.maskRange(span.offset, fill)
  }

  if (assert && remediatedSpans > 0) {
    throw new StatusMismatchError(packetIndex, firstProtocol, remediatedSpans)
  }

  return { remediatedSpans }
}

/** Dev/test builds enable assert when MODE is test (Vite/Vitest). */
export function statusInvariantAssertDefault(): boolean {
  try {
    return import.meta.env?.MODE === 'test'
  } catch {
    return false
  }
}
