/**
 * Enterprise export gate — independent of profile (T08 three-state).
 *
 * Data model (never mix):
 *   profile:  diagnostic | high-privacy
 *   gate:     AI_READY | AI_READY_WITH_GAPS | NOT_AI_READY
 *   validity: capture_structure / network_checksums / application_structure / cryptographic_integrity
 *
 * cryptographic_integrity == MODIFIED is NOT a reason for NOT_AI_READY.
 */

import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel'

/** Canonical T08 gate results. */
export const GATE_RESULTS = [
  'AI_READY',
  'AI_READY_WITH_GAPS',
  'NOT_AI_READY',
] as const

export type GateResult = (typeof GATE_RESULTS)[number]

/** @deprecated Prefer GateResult — same when non-null. */
export type GateBadge = GateResult

/** Legacy wire values accepted by {@link normalizeGateResult}. */
export const LEGACY_GATE_RESULTS = [
  'SAFE_FOR_AI',
  'SANITIZATION_INCOMPLETE',
] as const

export type LegacyGateResult = (typeof LEGACY_GATE_RESULTS)[number]

/**
 * Structured gate inputs. Steps 2–5 populate these from coverage/leak scan;
 * T08 adds disposition-based failClosed / exposed region counts.
 */
export interface ExportGateChecks {
  /**
   * @deprecated Prefer {@link exposedRegions}. Kept for older call sites;
   * treated as exposed when `exposedRegions` is omitted.
   */
  readonly unhandledUnverifiedRegions: number
  readonly leakHits: number
  readonly secretPassthroughBytes: number
  readonly prohibitedMetadataBlocks: number
  readonly verificationFatalErrors: number
  /**
   * True when nothing remains readable (exposedRegions/secret/leak all zero).
   * Fail-closed gaps do not make this false.
   */
  readonly coverageComplete: boolean
  /** Regions fail-closed masked/truncated/dropped without full analysis (→ gaps). */
  readonly failClosedRegions?: number
  /** Regions that may still expose content (→ not AI ready). */
  readonly exposedRegions?: number
  /** Value-free incident count from plan / text session (→ gaps when > 0). */
  readonly incidentCount?: number
  /** Diagnostic packet invariants — N/A for high-privacy when drops are allowed. */
  readonly packetCountInvariant?: 'PASS' | 'FAIL' | 'N/A'
  readonly packetOrderInvariant?: 'PASS' | 'FAIL' | 'N/A'
  readonly packetLengthInvariant?: 'PASS' | 'FAIL' | 'N/A'
  readonly timestampDeltaInvariant?: 'PASS' | 'FAIL' | 'N/A'
}

export interface ResolveExportGateInput {
  readonly profile: PcapAnonymizationLevel
  readonly checks?: ExportGateChecks
  /** Coarse incomplete signal (step 1 / correlation completion). */
  readonly sanitizationIncomplete?: boolean
  /** Hard export block (plan/container fatal). */
  readonly exportBlocked?: boolean
  /**
   * When true with exposed content, export may proceed after user ack
   * (confirm-exposed). Default false → NOT_AI_READY blocks export.
   */
  readonly unsafeExportAcknowledged?: boolean
}

export interface ExportGateOutcome {
  readonly profile: PcapAnonymizationLevel
  readonly gate: GateResult
  readonly exportAllowed: boolean
  /** True only for AI_READY (shareable-with-AI badge). */
  readonly safeForAi: boolean
  /** True for AI_READY or AI_READY_WITH_GAPS. */
  readonly aiReadyWithGaps: boolean
}

export function isGateResult(value: unknown): value is GateResult {
  return (
    value === 'AI_READY'
    || value === 'AI_READY_WITH_GAPS'
    || value === 'NOT_AI_READY'
    || value === 'SAFE_FOR_AI'
    || value === 'SANITIZATION_INCOMPLETE'
  )
}

/** @deprecated Prefer isGateResult. */
export const isGateBadge = isGateResult

/** Map legacy / current wire values to canonical GateResult. */
export function normalizeGateResult(value: unknown): GateResult | null {
  if (value === 'AI_READY' || value === 'SAFE_FOR_AI') return 'AI_READY'
  if (value === 'AI_READY_WITH_GAPS') return 'AI_READY_WITH_GAPS'
  if (value === 'NOT_AI_READY' || value === 'SANITIZATION_INCOMPLETE') return 'NOT_AI_READY'
  return null
}

function invariantOk(v: 'PASS' | 'FAIL' | 'N/A' | undefined): boolean {
  return v === undefined || v === 'PASS' || v === 'N/A'
}

function exposedFromChecks(c: ExportGateChecks): number {
  if (c.exposedRegions !== undefined) return c.exposedRegions
  return c.unhandledUnverifiedRegions
}

function failClosedFromChecks(c: ExportGateChecks): number {
  return c.failClosedRegions ?? 0
}

function hasExposed(c: ExportGateChecks): boolean {
  return (
    exposedFromChecks(c) > 0
    || c.leakHits > 0
    || c.secretPassthroughBytes > 0
    || c.prohibitedMetadataBlocks > 0
    || c.verificationFatalErrors > 0
  )
}

function hasGaps(c: ExportGateChecks): boolean {
  return failClosedFromChecks(c) > 0 || (c.incidentCount ?? 0) > 0
}

function invariantsFail(c: ExportGateChecks, profile: PcapAnonymizationLevel): boolean {
  if (profile !== 'diagnostic') return false
  return !(
    invariantOk(c.packetCountInvariant)
    && invariantOk(c.packetOrderInvariant)
    && invariantOk(c.packetLengthInvariant)
    && invariantOk(c.timestampDeltaInvariant)
  )
}

/**
 * Resolve gate for either profile.
 * High-privacy may carry AI_READY when the output is clean (gate describes output, not level).
 */
export function resolveExportGate(input: ResolveExportGateInput): ExportGateOutcome {
  const profile = input.profile

  if (input.exportBlocked) {
    return {
      profile,
      gate: 'NOT_AI_READY',
      exportAllowed: false,
      safeForAi: false,
      aiReadyWithGaps: false,
    }
  }

  if (!input.checks) {
    if (input.sanitizationIncomplete === true) {
      // Coarse incomplete without disposition detail — fail closed (NOT_AI_READY).
      return {
        profile,
        gate: 'NOT_AI_READY',
        exportAllowed: false,
        safeForAi: false,
        aiReadyWithGaps: false,
      }
    }
    // High-privacy may carry AI_READY: gate describes output cleanliness, not level.
    return {
      profile,
      gate: 'AI_READY',
      exportAllowed: true,
      safeForAi: true,
      aiReadyWithGaps: false,
    }
  }

  const c = input.checks
  if (invariantsFail(c, profile) || hasExposed(c)) {
    const acknowledged = input.unsafeExportAcknowledged === true
    return {
      profile,
      gate: 'NOT_AI_READY',
      exportAllowed: acknowledged,
      safeForAi: false,
      aiReadyWithGaps: false,
    }
  }

  if (hasGaps(c)) {
    return {
      profile,
      gate: 'AI_READY_WITH_GAPS',
      exportAllowed: true,
      safeForAi: false,
      aiReadyWithGaps: true,
    }
  }

  if (c.coverageComplete === false) {
    // Incomplete without classified gaps/exposed (e.g. plan blocked) → not AI ready.
    return {
      profile,
      gate: 'NOT_AI_READY',
      exportAllowed: false,
      safeForAi: false,
      aiReadyWithGaps: false,
    }
  }

  return {
    profile,
    gate: 'AI_READY',
    exportAllowed: true,
    safeForAi: true,
    aiReadyWithGaps: false,
  }
}

export function gateBadgeFromShareableWithAi(shareableWithAi: boolean): GateResult {
  return shareableWithAi ? 'AI_READY' : 'NOT_AI_READY'
}

/**
 * Worst-of aggregation for correlation (AI_READY < WITH_GAPS < NOT_AI_READY).
 */
export function worstGateResult(a: GateResult, b: GateResult): GateResult {
  const rank = (g: GateResult): number => {
    switch (g) {
      case 'AI_READY':
        return 0
      case 'AI_READY_WITH_GAPS':
        return 1
      case 'NOT_AI_READY':
        return 2
      default:
        return 2
    }
  }
  return rank(a) >= rank(b) ? a : b
}

export function isSafeForAi(gate: GateResult | null | undefined): boolean {
  return normalizeGateResult(gate) === 'AI_READY'
}

export function isAiReadyWithGaps(gate: GateResult | null | undefined): boolean {
  return normalizeGateResult(gate) === 'AI_READY_WITH_GAPS'
}

/**
 * Text-session gate: disabled/failed rules → NOT_AI_READY; line isolation incidents → gaps;
 * exposed (user-disabled) entities → NOT_AI_READY; clean → AI_READY.
 */
export function resolveTextExportGate(input: {
  readonly failedRuleIds: readonly string[]
  readonly incidentCount?: number
  readonly exposedEntityCount?: number
  /** Profile label for outcome; text uses diagnostic-equivalent semantics. */
  readonly profile?: PcapAnonymizationLevel
}): ExportGateOutcome {
  const profile = input.profile ?? 'diagnostic'
  if (input.failedRuleIds.length > 0 || (input.exposedEntityCount ?? 0) > 0) {
    return {
      profile,
      gate: 'NOT_AI_READY',
      exportAllowed: (input.exposedEntityCount ?? 0) > 0 && input.failedRuleIds.length === 0,
      safeForAi: false,
      aiReadyWithGaps: false,
    }
  }
  if ((input.incidentCount ?? 0) > 0) {
    return {
      profile,
      gate: 'AI_READY_WITH_GAPS',
      exportAllowed: true,
      safeForAi: false,
      aiReadyWithGaps: true,
    }
  }
  return {
    profile,
    gate: 'AI_READY',
    exportAllowed: true,
    safeForAi: true,
    aiReadyWithGaps: false,
  }
}
