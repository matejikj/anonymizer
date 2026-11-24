/**
 * Enterprise step 5 / T08 — byte-range coverage bookkeeping for sanitization-report + gate.
 * Counts from resulting disposition (not raw span status). Never embeds original values.
 *
 * Heuristic scanner (D3): still runs for identity discovery / recovery indexing (T09).
 * Gate decisions use disposition of those spans after policy apply — not heuristic status alone.
 */

import type { LayerCoverage, SanitizationPolicy } from '../sanitize/types'
import {
  resolveCoverageDisposition,
  type CoverageDisposition,
} from '../sanitize/coverageDisposition'
import type { PcapPlanSnapshot } from '../export/planSnapshot'
import type { ExportGateChecks } from './exportGate'
import { emptyPlanChangeCounts } from '../plan/planDisposition'
import {
  isPcapAnonymizationLevel,
  presetToSanitizationPolicy,
} from '../profile/presets'

const FAIL_CLOSED_DISPOSITIONS = new Set<CoverageDisposition>([
  'mask-in-place',
  'mask-application-in-place',
  'truncate',
  'drop',
  'strip-media-payload',
])

const EXPOSED_DISPOSITIONS = new Set<CoverageDisposition>([
  'preserve-unsafe',
])

export interface SanitizationCoverageSummary {
  readonly mappedSpanCount: number
  readonly maskedSpanCount: number
  readonly redactedSpanCount: number
  readonly preservedEncryptedSpanCount: number
  readonly preservedForDiagnosticsSpanCount: number
  /**
   * @deprecated Prefer {@link exposedRegions} + {@link failClosedRegions}.
   * Equals exposedRegions for gate compatibility with older readers.
   */
  readonly unhandledUnverifiedRegions: number
  /** Regions fail-closed without full analysis (→ AI_READY_WITH_GAPS). */
  readonly failClosedRegions: number
  /** Regions that may still expose content (→ NOT_AI_READY). */
  readonly exposedRegions: number
  /** Value-free incident count from plan / text session. */
  readonly incidentCount: number
  readonly secretPassthroughBytes: number
  /** PCAPNG DSB/NRB/ISB dropped on ingest (writer never re-emits them). */
  readonly droppedMetadataBlocks: number
  readonly dsbDropped: number
  readonly nrbDropped: number
  /** Place-holder until steps 6–8 classify crypto-invalidated fields precisely. */
  readonly cryptoInvalidatedCount: number
  /**
   * True when nothing remains readable (no exposed regions / secret passthrough / plan blocked).
   * Fail-closed gaps do not make this false.
   */
  readonly coverageComplete: boolean
  readonly prohibitedMetadataBlocks: number
}

function policyForPlan(
  plan: PcapPlanSnapshot,
  policy?: Pick<
    SanitizationPolicy,
    'unsupportedPayloadPolicy' | 'malformedPayloadPolicy' | 'mediaPolicy' | 'preset'
  >,
): Pick<
  SanitizationPolicy,
  'unsupportedPayloadPolicy' | 'malformedPayloadPolicy' | 'mediaPolicy' | 'preset'
> {
  if (policy) return policy
  const level = isPcapAnonymizationLevel(plan.pcapLevel) ? plan.pcapLevel : 'diagnostic'
  return presetToSanitizationPolicy(level)
}

function classifyDisposition(d: CoverageDisposition): 'fail-closed' | 'exposed' | 'other' {
  if (FAIL_CLOSED_DISPOSITIONS.has(d)) return 'fail-closed'
  if (EXPOSED_DISPOSITIONS.has(d)) return 'exposed'
  return 'other'
}

export function summarizeSanitizationCoverage(input: {
  readonly plan: PcapPlanSnapshot
  readonly coverage?: readonly LayerCoverage[]
  readonly unsupportedLayers?: number
  /** From PCAPNG reader — DSB+NRB+ISB skipped on ingest. */
  readonly droppedMetadataBlocks?: number
  readonly dsbDropped?: number
  readonly nrbDropped?: number
  readonly cryptoInvalidatedCount?: number
  /** Override policy (defaults from plan.pcapLevel). */
  readonly policy?: Pick<
    SanitizationPolicy,
    'unsupportedPayloadPolicy' | 'malformedPayloadPolicy' | 'mediaPolicy' | 'preset'
  >
  /** Override incident count (defaults from plan.incidents.totalFailures). */
  readonly incidentCount?: number
}): SanitizationCoverageSummary {
  const totals = input.plan.changeCategoryTotals ?? emptyPlanChangeCounts()
  const coverage = input.coverage ?? []
  const policy = policyForPlan(input.plan, input.policy)

  let failClosedRegions = 0
  let exposedRegions = 0
  let secretPassthroughBytes = 0

  for (const span of coverage) {
    const disposition = resolveCoverageDisposition(policy, span.status, span.protocol)
    const kind = classifyDisposition(disposition)
    if (kind === 'fail-closed') {
      failClosedRegions += 1
    } else if (kind === 'exposed') {
      exposedRegions += 1
      secretPassthroughBytes += Math.max(0, span.length)
    }
  }

  // Session-level unsupported layers that never produced a span still count.
  const unsupportedLayers = input.unsupportedLayers ?? 0
  if (unsupportedLayers > 0 && failClosedRegions === 0 && exposedRegions === 0) {
    const disposition = resolveCoverageDisposition(policy, 'unsupported', 'generic')
    const kind = classifyDisposition(disposition)
    if (kind === 'fail-closed') failClosedRegions += unsupportedLayers
    else if (kind === 'exposed') exposedRegions += unsupportedLayers
  }

  const droppedMetadataBlocks = input.droppedMetadataBlocks ?? 0
  const dsbDropped = input.dsbDropped ?? 0
  const nrbDropped = input.nrbDropped ?? 0
  // Writer always strips DSB/NRB — residual prohibited blocks in *output* are 0.
  const prohibitedMetadataBlocks = 0

  const incidentCount =
    input.incidentCount
    ?? input.plan.incidents?.totalFailures
    ?? 0

  // Nothing readable left — gaps (fail-closed / incidents) are allowed.
  const coverageComplete =
    exposedRegions === 0
    && secretPassthroughBytes === 0
    && (input.plan.packets.length === 0 || totals.blocked === 0)

  return {
    mappedSpanCount: totals.mapped,
    maskedSpanCount: totals['masked-content'],
    redactedSpanCount: totals.redacted,
    preservedEncryptedSpanCount: totals['preserved-encrypted'],
    preservedForDiagnosticsSpanCount: totals['preserved-for-diagnostics'],
    unhandledUnverifiedRegions: exposedRegions,
    failClosedRegions,
    exposedRegions,
    incidentCount,
    secretPassthroughBytes,
    droppedMetadataBlocks,
    dsbDropped,
    nrbDropped,
    cryptoInvalidatedCount: input.cryptoInvalidatedCount ?? 0,
    coverageComplete,
    prohibitedMetadataBlocks,
  }
}

export function buildGateChecksFromCoverage(input: {
  readonly coverage: SanitizationCoverageSummary
  readonly leakHits: number
  readonly verificationFatalErrors: number
  readonly profile: 'diagnostic' | 'high-privacy'
  readonly diagnosticInvariantOk?: boolean
}): ExportGateChecks {
  const diagnostic = input.profile === 'diagnostic'
  const inv: 'PASS' | 'FAIL' | 'N/A' = diagnostic
    ? (input.diagnosticInvariantOk === false ? 'FAIL' : 'PASS')
    : 'N/A'

  return {
    unhandledUnverifiedRegions: input.coverage.exposedRegions,
    failClosedRegions: input.coverage.failClosedRegions,
    exposedRegions: input.coverage.exposedRegions,
    incidentCount: input.coverage.incidentCount,
    leakHits: input.leakHits,
    secretPassthroughBytes: input.coverage.secretPassthroughBytes,
    prohibitedMetadataBlocks: input.coverage.prohibitedMetadataBlocks,
    verificationFatalErrors: input.verificationFatalErrors,
    coverageComplete: input.coverage.coverageComplete,
    packetCountInvariant: inv,
    packetOrderInvariant: inv,
    packetLengthInvariant: inv,
    timestampDeltaInvariant: inv,
  }
}
