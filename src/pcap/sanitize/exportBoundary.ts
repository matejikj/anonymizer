/**
 * CF-09 — safe export boundary vs parser progress.
 *
 * `parsedEnd` reflects how far decoders walked (diagnostic). Truncation and export
 * safety use `safeExportEnd`, which advances through contiguous bytes covered by
 * safe statuses (`covered`, `redacted`, `encrypted`, `truncated`) and through
 * `preserved-unsafe` (CF-11 fingerprint / media preserve — exported with risk).
 * Blocking spans (`unsupported`, `malformed`, `requires-reassembly`, `heuristic`)
 * terminate the safe prefix. T64: the same boundary runs for reassembly-overlay packets
 * (structural coverage ∪ projected overlay coverage), so heuristic is always masked or
 * truncated — never left as passthrough on TCP-reassembled HTTP/SIP segments.
 */

import { resolveBlockingExportDisposition } from './coverageDisposition.ts';
import type { CoverageStatus, LayerCoverage, SanitizationPolicy } from './types';

export type ExportDisposition =
  | 'keep'
  | 'truncate'
  | 'drop'
  | 'preserve-unsafe'
  | 'mask-in-place'
  | 'mask-application-in-place';

export interface ExportBoundaryResult {
  /** Furthest byte offset touched by any coverage span (diagnostic). */
  readonly parsedEnd: number;
  /** Contiguous exportable prefix length. */
  readonly safeExportEnd: number;
  readonly disposition: ExportDisposition;
}

const SAFE_STATUSES = new Set<CoverageStatus>([
  'covered',
  'redacted',
  'encrypted',
  'truncated',
  'preserved-for-diagnostics',
  'preserved-safe',
]);

/** Exportable with residual privacy risk — does not truncate (CF-11). */
const EXPORTABLE_RISKY_STATUSES = new Set<CoverageStatus>([
  'preserved-unsafe',
]);

const BLOCKING_STATUSES = new Set<CoverageStatus>([
  'unsupported',
  'malformed',
  'requires-reassembly',
  'heuristic',
  'processing-failed',
]);

function spansCoveringByte(coverage: readonly LayerCoverage[], byte: number): CoverageStatus[] {
  const hits: CoverageStatus[] = [];
  for (const span of coverage) {
    if (byte >= span.offset && byte < span.offset + span.length) {
      hits.push(span.status);
    }
  }
  return hits;
}

function regionStatus(coverage: readonly LayerCoverage[], start: number): CoverageStatus | null {
  const statuses = spansCoveringByte(coverage, start);
  if (statuses.length === 0) return null;
  if (statuses.some((s) => BLOCKING_STATUSES.has(s))) {
    return statuses.find((s) => BLOCKING_STATUSES.has(s)) ?? statuses[0]!;
  }
  if (statuses.some((s) => EXPORTABLE_RISKY_STATUSES.has(s))) {
    return 'preserved-unsafe';
  }
  if (statuses.every((s) => SAFE_STATUSES.has(s))) {
    return statuses[0]!;
  }
  return statuses[0]!;
}

function collectBreakpoints(coverage: readonly LayerCoverage[], packetLength: number): number[] {
  const points = new Set<number>([0, packetLength]);
  for (const span of coverage) {
    points.add(span.offset);
    points.add(Math.min(span.offset + span.length, packetLength));
  }
  return [...points].sort((a, b) => a - b);
}

/**
 * Derive export-safe byte length from sanitizer coverage spans.
 */
export function resolveExportBoundary(
  coverage: readonly LayerCoverage[],
  policy: SanitizationPolicy,
  packetLength: number,
): ExportBoundaryResult {
  const parsedEnd = Math.min(
    packetLength,
    coverage.reduce((max, span) => Math.max(max, span.offset + span.length), 0),
  );

  const breakpoints = collectBreakpoints(coverage, packetLength);
  let safeExportEnd = 0;
  let sawPreservedUnsafe = false;

  for (let i = 0; i < breakpoints.length - 1; i++) {
    const start = breakpoints[i]!;
    const end = breakpoints[i + 1]!;
    if (start >= packetLength) break;
    if (start > safeExportEnd) break;

    const status = regionStatus(coverage, start);
    if (status === null) break;
    if (BLOCKING_STATUSES.has(status)) break;
    if (EXPORTABLE_RISKY_STATUSES.has(status)) {
      sawPreservedUnsafe = true;
      safeExportEnd = end;
      continue;
    }
    if (SAFE_STATUSES.has(status)) {
      safeExportEnd = end;
    } else {
      break;
    }
  }

  let disposition: ExportDisposition = 'keep';
  if (safeExportEnd < packetLength) {
    const blocking = regionStatus(coverage, safeExportEnd);
    const resolved = resolveBlockingExportDisposition(policy, blocking);
    if (
      resolved === 'truncate'
      || resolved === 'drop'
      || resolved === 'preserve-unsafe'
      || resolved === 'mask-in-place'
      || resolved === 'mask-application-in-place'
    ) {
      disposition = resolved;
    } else if (sawPreservedUnsafe || coverage.some((c) => c.status === 'preserved-unsafe')) {
      disposition = 'preserve-unsafe';
    } else {
      disposition = 'keep';
    }
  } else if (sawPreservedUnsafe || coverage.some((c) => c.status === 'preserved-unsafe')) {
    disposition = 'preserve-unsafe';
  }

  return { parsedEnd, safeExportEnd, disposition };
}

/** True when a blocking span caps safeExportEnd at its start (property-test helper). */
export function blockingSpanCapsSafeEnd(
  coverage: readonly LayerCoverage[],
  packetLength: number,
): boolean {
  const { safeExportEnd } = resolveExportBoundary(
    coverage,
    {
      truncateUnsupported: true,
      unsupportedPayloadPolicy: 'truncate',
      malformedPayloadPolicy: 'drop',
    } as SanitizationPolicy,
    packetLength,
  );

  for (const span of coverage) {
    if (!BLOCKING_STATUSES.has(span.status)) continue;
    const spanEnd = span.offset + span.length;
    if (span.offset < safeExportEnd && spanEnd > safeExportEnd) {
      return false;
    }
    if (span.offset === safeExportEnd && spanEnd > safeExportEnd) {
      return true;
    }
    if (span.offset < safeExportEnd && spanEnd <= safeExportEnd) {
      return false;
    }
  }
  return true;
}
