/**
 * T10 — anonymization outcome view model (pure TS, no React).
 * Aggregates coverage families (T09), gate (T08), and incidents (T04/T07)
 * into one summary for UI + report / ai-diagnostics.
 */

import type { IncidentLogSnapshot, AnonymizationIncident } from '../../domain/anonymizationIncident'
import { cs } from '../../i18n/cs.ts'
import type { GateResult } from '../trust/exportGate'
import type { PcapPlanSnapshot } from '../export/planSnapshot'
import type { UnifiedProtocolSummary } from './types'
import {
  coverageStatusToUiStatus,
  dominantUiStatus,
  layerKindFromCounts,
  userVerdictForProtocol,
  type PcapProtocolCoverageRow,
} from './pcapCoverageViewModel'
import {
  buildSupportRequestClipboard,
  supportRequestUserMessage,
  type SupportRequestItem,
} from '../docs/protocolSupportMatrix.ts'
import { familyForProtocol, isUnsupportedProtocolId, protocolFamilyLabel } from './protocolFamilies'
import { protocolPrivacyGuidance } from './protocolPrivacyGuidance'

export const OUTCOME_FAMILY_STATES = [
  'anonymized',
  'masked-without-analysis',
  'encrypted-kept',
  'needs-attention',
  'processing-failed',
] as const

export type OutcomeFamilyState = (typeof OUTCOME_FAMILY_STATES)[number]

export interface OutcomeFamilyRow {
  readonly familyId: string
  readonly familyLabel: string
  readonly state: OutcomeFamilyState
  readonly stateLabel: string
  readonly packetCount: number
  readonly explanation: string
  readonly recommendation: string
  /** Protocol id for filterPacketIndices / display filter. */
  readonly filterProtocol: string | null
  readonly probable: boolean
  readonly protocols: readonly OutcomeProtocolRow[]
}

export interface OutcomeProtocolRow {
  readonly id: string
  readonly label: string
  readonly state: OutcomeFamilyState
  readonly method: string
  readonly check: string
  readonly needsReview: boolean
}

export interface OutcomeIncidentRow {
  readonly packetNumber?: number
  readonly lineNumber?: number
  readonly protocol?: string
  readonly reasonLabel: string
  readonly fallbackLabel: string
}

export interface OutcomeSupportRequest {
  readonly code: string
  readonly family: string
  readonly packetCount: number
  readonly flowCount: number
  readonly message: string
  readonly clipboardText: string
}

export interface AnonymizationOutcome {
  readonly summarySentence: string
  readonly gate: GateResult
  readonly gateLabel: string
  readonly families: readonly OutcomeFamilyRow[]
  readonly incidents: readonly OutcomeIncidentRow[]
  readonly incidentTotal: number
  readonly incidentMoreCount: number
  readonly maskedPacketRanges: readonly string[]
  /** T32 — identified unsupported protocols; copy request without file/originals. */
  readonly supportRequests: readonly OutcomeSupportRequest[]
  readonly diagnosticImpact: {
    readonly analyzableFamilyCount: number
    readonly maskedWithoutAnalysisFamilyCount: number
    readonly needsAttentionFamilyCount: number
    readonly processingFailedPacketCount: number
  }
}

const STATE_RANK: Record<OutcomeFamilyState, number> = {
  anonymized: 0,
  'encrypted-kept': 1,
  'masked-without-analysis': 2,
  'processing-failed': 3,
  'needs-attention': 4,
}

const MAX_INCIDENTS_SHOWN = 50

function worseState(a: OutcomeFamilyState, b: OutcomeFamilyState): OutcomeFamilyState {
  return STATE_RANK[a] >= STATE_RANK[b] ? a : b
}

function stateFromProtocolRow(row: PcapProtocolCoverageRow): OutcomeFamilyState {
  if (row.dominantStatus === 'processing-failed') return 'processing-failed'
  if (
    row.userVerdict === 'unsupported-preserved'
    || row.userVerdict === 'recognized-risk-diagnostic'
    || row.userVerdict === 'blocking'
    || row.userVerdict === 'malformed'
    || row.dominantUiStatus === 'exposed'
    || row.dominantUiStatus === 'blocked'
  ) {
    return 'needs-attention'
  }
  if (row.dominantStatus === 'encrypted' || row.userVerdict === 'encrypted-preserved') {
    return 'encrypted-kept'
  }
  if (
    // Missing legacy decode detail does not mean the sanitizer masked the whole payload.
    // A covered protocol was parsed/sanitized; fail-closed dispositions remain explicit below.
    (row.userVerdict === 'protected-export-no-full-analysis' && row.dominantStatus !== 'covered')
    || row.userVerdict === 'heuristic'
    || row.userVerdict === 'requires-reassembly'
    || row.userVerdict === 'recognized-truncated-safe'
    || row.dominantStatus === 'heuristic'
    || row.dominantStatus === 'truncated'
    || row.dominantStatus === 'unsupported'
    || row.dominantStatus === 'requires-reassembly'
    || row.probableIdentification
  ) {
    return 'masked-without-analysis'
  }
  return 'anonymized'
}

function stateLabel(state: OutcomeFamilyState): string {
  return cs.pcap.outcome.familyState[state]
}

function explanationFor(state: OutcomeFamilyState, packetCount: number, probable: boolean): string {
  const base = cs.pcap.outcome.familyExplanation[state].replace('{n}', String(packetCount))
  return probable ? `${base} ${cs.pcap.outcome.probableNote}` : base
}

function recommendationFor(
  state: OutcomeFamilyState,
  gate: GateResult,
  preset: 'diagnostic' | 'high-privacy',
  packetCount: number,
): string {
  const n = String(packetCount)
  switch (state) {
    case 'anonymized':
      return cs.pcap.outcome.recommend.anonymized
    case 'encrypted-kept':
      return cs.pcap.outcome.recommend.encryptedKept
    case 'masked-without-analysis':
      return (gate === 'AI_READY_WITH_GAPS'
        ? cs.pcap.outcome.recommend.maskedGaps
        : cs.pcap.outcome.recommend.masked
      ).replace('{n}', n)
    case 'processing-failed':
      return cs.pcap.outcome.recommend.processingFailed
    case 'needs-attention':
      return preset === 'diagnostic'
        ? cs.pcap.outcome.recommend.needsAttentionDiagnostic
        : cs.pcap.outcome.recommend.needsAttentionHighPrivacy
    default:
      return cs.pcap.outcome.recommend.masked.replace('{n}', n)
  }
}

function reasonLabel(reason: AnonymizationIncident['reason']): string {
  return cs.pcap.outcome.incidentReason[reason] ?? cs.pcap.outcome.incidentReason.unknown
}

function fallbackLabel(fallback: AnonymizationIncident['fallback']): string {
  return cs.pcap.outcome.incidentFallback[fallback] ?? fallback
}

/** Compact sorted packet numbers into `"317-320"` / `"322"` strings. */
export function compactPacketRanges(numbers: readonly number[]): string[] {
  const sorted = [...new Set(numbers.filter((n) => Number.isFinite(n) && n > 0))].sort((a, b) => a - b)
  if (sorted.length === 0) return []
  const out: string[] = []
  let start = sorted[0]!
  let prev = start
  for (let i = 1; i < sorted.length; i++) {
    const n = sorted[i]!
    if (n === prev + 1) {
      prev = n
      continue
    }
    out.push(start === prev ? String(start) : `${start}-${prev}`)
    start = n
    prev = n
  }
  out.push(start === prev ? String(start) : `${start}-${prev}`)
  return out
}

/**
 * Compact masked/fail-closed packet numbers for report / ai-diagnostics.
 * Export path only — do not call from React render for large captures.
 */
export function computeMaskedPacketRanges(plan: PcapPlanSnapshot): string[] {
  const nums: number[] = []
  for (const p of plan.packets) {
    const masked = (p.maskedByteCount ?? 0) > 0 || (p.changeCounts?.['masked-content'] ?? 0) > 0
    const failed = p.dispositionReason === 'blocked'
    if (masked || failed) nums.push(p.packetNumber)
  }
  for (const inc of plan.incidents?.incidents ?? []) {
    if (inc.packetNumber != null) nums.push(inc.packetNumber)
  }
  return compactPacketRanges(nums)
}

function gateLabel(gate: GateResult): string {
  switch (gate) {
    case 'AI_READY':
      return cs.pcap.coverageUx.gateAiReady
    case 'AI_READY_WITH_GAPS':
      return cs.pcap.coverageUx.gateAiReadyWithGaps
    case 'NOT_AI_READY':
      return cs.pcap.coverageUx.gateNotAiReady
    default:
      return cs.pcap.coverageUx.gateNotAiReady
  }
}

function buildSummarySentence(input: {
  gate: GateResult
  familyLabels: readonly string[]
  needsAttention: readonly string[]
  masked: readonly string[]
}): string {
  const listed = input.familyLabels.slice(0, 6)
  const protocols =
    listed.length === 0
      ? cs.pcap.outcome.summaryNoProtocols
      : listed.join(', ')
  if (input.gate === 'AI_READY') {
    return cs.pcap.outcome.summaryAiReady.replace('{protocols}', protocols)
  }
  if (input.gate === 'AI_READY_WITH_GAPS') {
    const gaps = input.masked.slice(0, 4).join(', ') || cs.pcap.outcome.summaryGenericGaps
    return cs.pcap.outcome.summaryWithGaps
      .replace('{protocols}', protocols)
      .replace('{gaps}', gaps)
  }
  const attention = input.needsAttention.slice(0, 4).join(', ') || cs.pcap.outcome.summaryGenericAttention
  return cs.pcap.outcome.summaryNotReady
    .replace('{protocols}', protocols)
    .replace('{attention}', attention)
}

/** One entry per detected protocol, merging its internal fields without hiding the worst result. */
function protocolDetails(rows: readonly PcapProtocolCoverageRow[], failed: readonly string[]): OutcomeProtocolRow[] {
  const details = new Map<string, OutcomeProtocolRow>()
  const heuristicIds = new Set<string>()
  for (const row of rows) {
    const guide = protocolPrivacyGuidance(row.protocol)
    let state = stateFromProtocolRow(row)
    const heuristic = heuristicIds.has(guide.id) || row.dominantStatus === 'heuristic' || row.userVerdict === 'heuristic'
    if (heuristic) heuristicIds.add(guide.id)
    if (!guide.known && state === 'anonymized') {
      state = row.dominantStatus === 'redacted' ? 'masked-without-analysis' : 'needs-attention'
    }
    const previous = details.get(guide.id)
    state = previous ? worseState(previous.state, state) : state
    const method = state === 'needs-attention' ? cs.pcap.outcome.protocolUnverified
      : state === 'processing-failed' ? cs.pcap.outcome.protocolFailed
      : state === 'masked-without-analysis' ? (heuristic ? cs.pcap.outcome.protocolHeuristic : cs.pcap.outcome.protocolLimited)
        : guide.method
    details.set(guide.id, {
      id: guide.id, label: guide.label, state, method,
      check: heuristic ? cs.pcap.outcome.checkHeuristic : guide.check,
      needsReview: previous?.needsReview === true || heuristic || state === 'needs-attention',
    })
  }
  const failedIds = new Set<string>()
  for (const protocol of failed) {
    const guide = protocolPrivacyGuidance(protocol)
    if (failedIds.has(guide.id)) continue
    failedIds.add(guide.id)
    const previous = details.get(guide.id)
    details.set(guide.id, {
      id: guide.id, label: guide.label,
      state: previous ? worseState(previous.state, 'processing-failed') : 'processing-failed',
      method: cs.pcap.outcome.protocolFailed,
      check: `${previous?.check ?? guide.check} ${cs.pcap.outcome.recommend.processingFailed}`,
      needsReview: previous?.needsReview ?? false,
    })
  }
  return [...details.values()].sort((a, b) => STATE_RANK[b.state] - STATE_RANK[a.state] || a.label.localeCompare(b.label, 'cs'))
}

export function buildAnonymizationOutcome(input: {
  readonly protocols: readonly PcapProtocolCoverageRow[]
  readonly gate: GateResult
  readonly plan: PcapPlanSnapshot
  readonly incidents?: IncidentLogSnapshot | null
  readonly preset: 'diagnostic' | 'high-privacy'
  readonly maxIncidentsShown?: number
  /**
   * Precomputed compact ranges (export path). UI omits this to avoid scanning
   * up to 1M plan packets on the main thread — use incident list instead.
   */
  readonly maskedPacketRanges?: readonly string[]
  /** The final byte-level export gate is authoritative; UI may be more conservative. */
  readonly source?: 'preview' | 'verified-export'
}): AnonymizationOutcome {
  const maxShown = input.maxIncidentsShown ?? MAX_INCIDENTS_SHOWN
  const incidentsSnap = input.incidents ?? input.plan.incidents ?? null

  type Acc = {
    familyId: string
    familyLabel: string
    state: OutcomeFamilyState
    packetCount: number
    filterProtocol: string | null
    probable: boolean
    hasFamilyPacketCount: boolean
    protocols: PcapProtocolCoverageRow[]
    failedProtocols: string[]
  }
  const byFamily = new Map<string, Acc>()

  for (const row of input.protocols) {
    if (row.recognizedPacketCount <= 0) continue
    const family = familyForProtocol(row.protocol)
    const familyId = row.familyId || family.familyId
    const state = stateFromProtocolRow(row)
    const prev = byFamily.get(familyId)
    if (!prev) {
      byFamily.set(familyId, {
        familyId,
        familyLabel: row.familyLabel || protocolFamilyLabel(family),
        state,
        packetCount: row.familyPacketCount ?? row.recognizedPacketCount,
        hasFamilyPacketCount: row.familyPacketCount !== undefined,
        filterProtocol: row.filterProtocol,
        probable: row.probableIdentification || family.probable,
        protocols: [row],
        failedProtocols: [],
      })
      continue
    }
    prev.state = worseState(prev.state, state)
    prev.protocols.push(row)
    if (row.familyPacketCount !== undefined) {
      prev.packetCount = prev.hasFamilyPacketCount ? Math.max(prev.packetCount, row.familyPacketCount) : row.familyPacketCount
      prev.hasFamilyPacketCount = true
    } else if (!prev.hasFamilyPacketCount) prev.packetCount += row.recognizedPacketCount
    prev.probable = prev.probable || row.probableIdentification || family.probable
    if (!prev.filterProtocol) prev.filterProtocol = row.filterProtocol
  }

  // Fold processing-failed incidents into family rows when protocol known
  for (const inc of incidentsSnap?.incidents ?? []) {
    if (!inc.protocol) continue
    const family = familyForProtocol(inc.protocol)
    const prev = byFamily.get(family.familyId)
    if (prev) {
      prev.state = worseState(prev.state, 'processing-failed')
      prev.failedProtocols.push(inc.protocol)
    } else {
      byFamily.set(family.familyId, {
        familyId: family.familyId,
        familyLabel: protocolFamilyLabel(family),
        state: 'processing-failed',
        packetCount: 1,
        hasFamilyPacketCount: false,
        filterProtocol: inc.protocol,
        probable: family.probable,
        protocols: [],
        failedProtocols: [inc.protocol],
      })
    }
  }

  const familyDetails = [...byFamily.values()].map(acc => {
    const protocols = protocolDetails(acc.protocols, acc.failedProtocols)
    return { ...acc, protocols, state: protocols.reduce((state, p) => worseState(state, p.state), acc.state) }
  })
  // A presentation must never be greener than its actual rows, even with stale/coarse gate input.
  const gate = input.source === 'verified-export' ? input.gate
    : familyDetails.some(f => f.state === 'needs-attention' || f.protocols.some(p => p.needsReview))
    ? 'NOT_AI_READY'
    : input.gate === 'AI_READY' && (familyDetails.some(f => f.state === 'masked-without-analysis' || f.state === 'processing-failed') || (incidentsSnap?.totalFailures ?? 0) > 0)
      ? 'AI_READY_WITH_GAPS' : input.gate
  const families: OutcomeFamilyRow[] = familyDetails
    .map((acc) => ({
      familyId: acc.familyId,
      familyLabel: acc.familyLabel,
      state: acc.state,
      stateLabel: stateLabel(acc.state),
      packetCount: acc.packetCount,
      explanation: explanationFor(acc.state, acc.packetCount, acc.probable),
      recommendation: recommendationFor(acc.state, gate, input.preset, acc.packetCount),
      filterProtocol: acc.filterProtocol,
      probable: acc.probable,
      protocols: acc.protocols,
    }))
    .sort((a, b) => STATE_RANK[b.state] - STATE_RANK[a.state] || b.packetCount - a.packetCount)

  const incidentRows: OutcomeIncidentRow[] = (incidentsSnap?.incidents ?? [])
    .slice(0, maxShown)
    .map((inc) => ({
      packetNumber: inc.packetNumber,
      lineNumber: inc.lineNumber,
      protocol: inc.protocol,
      reasonLabel: reasonLabel(inc.reason),
      fallbackLabel: fallbackLabel(inc.fallback),
    }))

  const incidentTotal = incidentsSnap?.totalFailures ?? incidentRows.length
  const incidentMoreCount = Math.max(0, incidentTotal - incidentRows.length)

  const summarySentence = buildSummarySentence({
    gate,
    familyLabels: families.map((f) => f.familyLabel),
    needsAttention: families.filter((f) => f.state === 'needs-attention' || f.protocols.some(p => p.needsReview)).map((f) => f.familyLabel),
    masked: families
      .filter((f) => f.state === 'masked-without-analysis' || f.state === 'processing-failed')
      .map((f) => f.familyLabel),
  })

  const supportRequests = buildUnsupportedSupportRequests(input.protocols)

  return {
    summarySentence,
    gate,
    gateLabel: gateLabel(gate),
    families,
    incidents: incidentRows,
    incidentTotal,
    incidentMoreCount,
    maskedPacketRanges: input.maskedPacketRanges ?? [],
    supportRequests,
    diagnosticImpact: {
      analyzableFamilyCount: families.filter((f) => f.state === 'anonymized' || f.state === 'encrypted-kept')
        .length,
      maskedWithoutAnalysisFamilyCount: families.filter((f) => f.state === 'masked-without-analysis')
        .length,
      needsAttentionFamilyCount: families.filter((f) => f.state === 'needs-attention').length,
      processingFailedPacketCount: families
        .filter((f) => f.state === 'processing-failed')
        .reduce((n, f) => n + f.packetCount, 0),
    },
  }
}

function buildUnsupportedSupportRequests(
  protocols: readonly PcapProtocolCoverageRow[],
): OutcomeSupportRequest[] {
  const byCode = new Map<string, SupportRequestItem>()
  for (const row of protocols) {
    if (row.recognizedPacketCount <= 0) continue
    if (!isUnsupportedProtocolId(row.protocol)) continue
    const prev = byCode.get(row.protocol)
    const family = protocolFamilyLabel(familyForProtocol(row.protocol))
    byCode.set(row.protocol, {
      code: row.protocol,
      family,
      packetCount: (prev?.packetCount ?? 0) + row.recognizedPacketCount,
      flowCount: prev?.flowCount ?? 0,
    })
  }
  return [...byCode.values()]
    .sort((a, b) => b.packetCount - a.packetCount || a.code.localeCompare(b.code))
    .map((item) => ({
      ...item,
      message: supportRequestUserMessage(item),
      clipboardText: buildSupportRequestClipboard([item]),
    }))
}

export type AnonymizationOutcomeReportSection = {
  readonly verdict: GateResult
  readonly summarySentence: string
  readonly families: readonly {
    readonly familyId: string
    readonly state: OutcomeFamilyState
    readonly packetCount: number
    readonly recommendation: string
  }[]
  readonly incidentTotal: number
  readonly incidentAggregates: readonly {
    readonly protocol: string
    readonly reason: string
    readonly fallback: string
    readonly count: number
  }[]
  readonly maskedPacketRanges: readonly string[]
  readonly diagnosticImpact: AnonymizationOutcome['diagnosticImpact']
}

/** Wire-safe projection for report / ai-diagnostics (no originals). */
export function anonymizationOutcomeForReport(
  outcome: AnonymizationOutcome,
  incidents?: IncidentLogSnapshot | null,
): AnonymizationOutcomeReportSection {
  return {
    verdict: outcome.gate,
    summarySentence: outcome.summarySentence,
    families: outcome.families.map((f) => ({
      familyId: f.familyId,
      state: f.state,
      packetCount: f.packetCount,
      recommendation: f.recommendation,
    })),
    incidentTotal: outcome.incidentTotal,
    incidentAggregates: incidentAggregatesForReport(incidents),
    maskedPacketRanges: outcome.maskedPacketRanges,
    diagnosticImpact: outcome.diagnosticImpact,
  }
}

export function incidentAggregatesForReport(
  snap: IncidentLogSnapshot | null | undefined,
): readonly { protocol: string; reason: string; fallback: string; count: number }[] {
  if (!snap) return []
  return snap.aggregates.map((a) => ({
    protocol: a.protocol,
    reason: a.reason,
    fallback: a.fallback,
    count: a.count,
  }))
}

/**
 * Build coverage rows from unified protocol summaries (export / report path).
 * Mirrors `buildPcapCoverageViewModel` protocol mapping without session statuses.
 */
export function coverageRowsFromProtocolSummaries(
  summaries: readonly UnifiedProtocolSummary[],
  preset: 'diagnostic' | 'high-privacy',
  truncateUnsupported = preset === 'high-privacy',
): PcapProtocolCoverageRow[] {
  return summaries.map((p) => {
    const layerKind = layerKindFromCounts(p.structuralSpanCount, p.sanitizerSpanCount)
    const userVerdict = userVerdictForProtocol({
      layerKind,
      dominantStatus: p.dominantStatus,
      truncateUnsupported,
      preset,
    })
    let ui = coverageStatusToUiStatus(p.dominantStatus)
    if (userVerdict === 'recognized-risk-diagnostic' || userVerdict === 'unsupported-preserved') {
      ui = dominantUiStatus(ui, 'exposed')
    }
    if (userVerdict === 'blocking' || p.dominantStatus === 'malformed') {
      ui = dominantUiStatus(ui, 'blocked')
    }
    const family = familyForProtocol(p.protocol)
    return {
      protocol: p.protocol,
      familyId: family.familyId,
      familyLabel: protocolFamilyLabel(family),
      probableIdentification: family.probable || isUnsupportedProtocolId(p.protocol),
      recognizedPacketCount: p.packetCount,
      familyPacketCount: p.familyPacketCount,
      protectedPacketCount: 0,
      layerKind,
      dominantStatus: p.dominantStatus,
      dominantUiStatus: ui,
      userVerdict,
      userVerdictLabel: '',
      technicalSourceLabel: '',
      unsupportedCount: p.unsupportedCount,
      filterProtocol: p.protocol,
    }
  })
}

/**
 * Export-path helper: coverage rows + full masked ranges from plan packets.
 * Safe to call once per export; not for React render loops.
 */
export function buildAnonymizationOutcomeForExport(input: {
  readonly protocolCoverage: readonly UnifiedProtocolSummary[]
  readonly gate: GateResult
  readonly plan: PcapPlanSnapshot
  readonly incidents?: IncidentLogSnapshot | null
  readonly preset: 'diagnostic' | 'high-privacy'
}): AnonymizationOutcomeReportSection {
  const protocols = coverageRowsFromProtocolSummaries(input.protocolCoverage, input.preset)
  const outcome = buildAnonymizationOutcome({
    protocols,
    gate: input.gate,
    plan: input.plan,
    incidents: input.incidents,
    preset: input.preset,
    maskedPacketRanges: computeMaskedPacketRanges(input.plan),
    source: 'verified-export',
  })
  return anonymizationOutcomeForReport(outcome, input.incidents ?? input.plan.incidents)
}
