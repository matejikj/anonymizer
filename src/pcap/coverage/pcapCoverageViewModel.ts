/**
 * Stage 6 — presentation coverage view model.
 * Derived only from unifiedCoverage + policy + plan + session statuses.
 * All PCAP UI surfaces must consume this — never reassemble from histogram ad-hoc.
 */

import type { CoverageStatus, LayerCoverage, SanitizationPolicy } from '../sanitize/types'
import { isPreserveUnsafeMediaPolicy } from '../sanitize/types'
import type { UnifiedCoverageModel, UnifiedCoverageStatus, UnifiedLayerCoverage } from './types'
import { coverageStatusLabel } from './statusLabels'
import { familyForProtocol, protocolFamilyLabel } from './protocolFamilies'
import { cs } from '../../i18n/cs.ts'
import type { PcapPlanSnapshot } from '../export/planSnapshot'
import { buildDiagnosticResidualRisk, resolveExportGate } from '../trust'
import { buildPrivacyReport } from '../privacy/privacyReport'
import { summarizeSanitizationCoverage, buildGateChecksFromCoverage } from '../trust/coverageBookkeeping'
import { policyFromLevel } from '../profile/pcapAnonymizationLevel'

/** Mirror of session status vocabularies — avoid importing ui/pcapSession (cycle). */
export type AnonymizationStatus = 'covered' | 'exposed' | 'blocked'
export type IntegrityStatus = 'ok' | 'warnings' | 'unverifiable'
export type CompatibilityStatus = 'valid' | 'valid-with-drops' | 'blocked'

export interface PcapSessionStatusSnapshot {
  readonly anonymization: AnonymizationStatus
  readonly integrity: IntegrityStatus
  readonly compatibility: CompatibilityStatus
  readonly truncatedCount: number
  readonly unsupportedCount: number
  readonly droppedCount: number
  readonly changedCount: number
  readonly reassemblyCount: number
  readonly issueCount: number
}

/** User-facing layer origin (technical source stays in tooltip/detail). */
export type CoverageLayerKind = 'structural' | 'sanitizer' | 'both' | 'none'

/**
 * Dominant UI status — same matrix for Overview, Coverage, detail, filter, strip, export.
 * Priority matches domain `dominantStatus` with session-level exposed/blocked overlays.
 */
export type DominantUiStatus =
  | 'blocked'
  | 'malformed'
  | 'unsupported'
  | 'requires-reassembly'
  | 'encrypted'
  | 'heuristic'
  | 'truncated'
  | 'exposed'
  | 'covered'

export type UserCoverageVerdict =
  | 'recognized-and-protected'
  | 'protected-export-no-full-analysis'
  | 'recognized-truncated-safe'
  | 'recognized-risk-diagnostic'
  | 'unsupported-preserved'
  | 'heuristic'
  | 'malformed'
  | 'requires-reassembly'
  | 'encrypted-preserved'
  | 'blocking'

/** Final export action for a significant span (Stage 6.1 / step 9 packet detail). */
export type SpanExportAction =
  | 'mapped'
  | 'redacted'
  | 'masked-content'
  | 'preserved-for-diagnostics'
  | 'rewritten'
  | 'preserved'
  | 'truncated'
  | 'heuristic'
  | 'unverifiable'
  | 'blocked'

export type PrimaryExportAction = 'export-safe' | 'confirm-exposed' | 'blocked' | 'inspect'

export interface PcapPreExportSummaryBucket {
  readonly id: 'removed' | 'kept' | 'blocked'
  readonly title: string
  readonly body: string
  readonly itemCount: number
}

export interface PcapProtocolCoverageRow {
  readonly protocol: string
  /** T09 — stable family id for grouping (UI panel is T10). */
  readonly familyId: string
  readonly familyLabel: string
  /** True when protocol id came from signature identification (`unsupported:*`). */
  readonly probableIdentification: boolean
  /** Packets where the protocol was recognized (structural and/or sanitizer). */
  readonly recognizedPacketCount: number
  readonly familyPacketCount?: number
  /** Packets where export will rewrite / truncate / heuristically alter the protocol. */
  readonly protectedPacketCount: number
  readonly layerKind: CoverageLayerKind
  readonly dominantStatus: UnifiedCoverageStatus
  readonly dominantUiStatus: DominantUiStatus
  readonly userVerdict: UserCoverageVerdict
  readonly userVerdictLabel: string
  /** Technical layer names — detail / tooltip only. */
  readonly technicalSourceLabel: string
  readonly unsupportedCount: number
  readonly filterProtocol: string
}

export interface PcapSpanCoverageRow {
  readonly protocol: string
  readonly offset: number
  readonly length: number
  readonly status: CoverageStatus
  readonly statusLabel: string
  readonly exportAction: SpanExportAction
  readonly exportActionLabel: string
  readonly layerKind: CoverageLayerKind
  readonly technicalSource: 'structural' | 'sanitizer'
  readonly needsAttention: boolean
}

export interface PcapCoverageSummary {
  readonly canExport: boolean
  readonly exportLooksSafe: boolean
  readonly primaryVerdict: string
  readonly primaryAction: PrimaryExportAction
  readonly primaryActionLabel: string
  /** At most three short reasons. */
  readonly reasons: readonly string[]
  readonly changedCount: number
  readonly removedCount: number
  readonly attentionCount: number
  readonly anonymization: AnonymizationStatus
  readonly integrity: IntegrityStatus
  readonly compatibility: CompatibilityStatus
  readonly anonymizationLabel: string
  readonly integrityLabel: string
  readonly compatibilityLabel: string
  /** Step 9 — three pre-export summaries. */
  readonly preExportSummaries: readonly PcapPreExportSummaryBucket[]
  readonly residualNote: string
  /** T08 — gate badge for overview (AI_READY / AI_READY_WITH_GAPS / NOT_AI_READY). */
  readonly gateBadge: 'AI_READY' | 'AI_READY_WITH_GAPS' | 'NOT_AI_READY'
  readonly gateBadgeLabel: string
  readonly diagnosticResidualRisk: {
    readonly graph: boolean
    readonly timing: boolean
    readonly topology: boolean
    readonly fingerprint: boolean
  }
  readonly residualRiskLabels: readonly string[]
}

export interface PcapCoverageViewModel {
  readonly planRevision: string
  readonly mappingRevision: number
  readonly generationId: string
  readonly summary: PcapCoverageSummary
  readonly protocols: readonly PcapProtocolCoverageRow[]
  spansForPacket(packetIndex: number): readonly PcapSpanCoverageRow[]
}

const UI_STATUS_PRIORITY: readonly DominantUiStatus[] = [
  'covered',
  'truncated',
  'exposed',
  'heuristic',
  'encrypted',
  'requires-reassembly',
  'unsupported',
  'malformed',
  'blocked',
]

export function dominantUiStatus(
  a: DominantUiStatus,
  b: DominantUiStatus,
): DominantUiStatus {
  const pa = UI_STATUS_PRIORITY.indexOf(a)
  const pb = UI_STATUS_PRIORITY.indexOf(b)
  return (pa >= pb ? a : b)
}

export function coverageStatusToUiStatus(status: CoverageStatus): DominantUiStatus {
  switch (status) {
    case 'covered':
    case 'redacted':
    case 'preserved-for-diagnostics':
      return 'covered'
    case 'truncated':
      return 'truncated'
    case 'heuristic':
      return 'heuristic'
    case 'preserved-unsafe':
      return 'exposed'
    case 'encrypted':
      return 'encrypted'
    case 'requires-reassembly':
      return 'requires-reassembly'
    case 'unsupported':
      return 'unsupported'
    case 'malformed':
      return 'malformed'
    case 'processing-failed':
      return 'malformed'
    default:
      return 'unsupported'
  }
}

export function spanExportAction(
  status: CoverageStatus,
  options: { readonly blocking?: boolean; readonly protocol?: string } = {},
): SpanExportAction {
  if (options.blocking) return 'blocked'
  const protocol = options.protocol ?? ''
  switch (status) {
    case 'covered':
      return 'mapped'
    case 'redacted':
      if (
        protocol === 'payload'
        || protocol === 'application'
        || protocol === 'rtp'
        || protocol === 'rtcp'
        || protocol === 'srtp'
        || protocol.includes('payload')
        || protocol.includes('mask')
      ) {
        return 'masked-content'
      }
      return 'redacted'
    case 'truncated':
      return 'truncated'
    case 'heuristic':
      return 'heuristic'
    case 'preserved-for-diagnostics':
      return 'preserved-for-diagnostics'
    case 'preserved-unsafe':
      return 'preserved'
    case 'requires-reassembly':
      return 'unverifiable'
    case 'malformed':
    case 'processing-failed':
      return 'blocked'
    case 'unsupported':
    case 'encrypted':
      return 'preserved'
    default:
      return 'preserved'
  }
}

export function layerKindFromCounts(
  structuralSpanCount: number,
  sanitizerSpanCount: number,
): CoverageLayerKind {
  if (structuralSpanCount > 0 && sanitizerSpanCount > 0) return 'both'
  if (sanitizerSpanCount > 0) return 'sanitizer'
  if (structuralSpanCount > 0) return 'structural'
  return 'none'
}

export function userVerdictForProtocol(input: {
  readonly layerKind: CoverageLayerKind
  readonly dominantStatus: UnifiedCoverageStatus
  readonly truncateUnsupported: boolean
  readonly preset: SanitizationPolicy['preset']
  /** Defaults to the fixed level's policy — what the export boundary applies to unsupported spans. */
  readonly unsupportedPayloadPolicy?: SanitizationPolicy['unsupportedPayloadPolicy']
}): UserCoverageVerdict {
  const { layerKind, dominantStatus: status, truncateUnsupported, preset } = input

  if (status === 'malformed') return 'malformed'
  if (status === 'requires-reassembly') return 'requires-reassembly'
  if (status === 'encrypted') return 'encrypted-preserved'
  if (status === 'preserved-unsafe') return 'recognized-risk-diagnostic'
  if (status === 'preserved-for-diagnostics') return 'recognized-and-protected'
  // Redacted content is masked in the export; it is protected, just not structurally analysed.
  if (status === 'redacted') return 'protected-export-no-full-analysis'

  if (layerKind === 'sanitizer' && (status === 'covered' || status === 'truncated')) {
    return 'protected-export-no-full-analysis'
  }

  // T64 — heuristic uses the same export-boundary policy matrix as unsupported (including
  // reassembly overlay paths); it is never left as a manual-review verdict.
  if (status === 'unsupported' || status === 'heuristic') {
    // high-privacy fail-closed: truncate/drop unsupported
    if (truncateUnsupported || preset === 'high-privacy') return 'recognized-truncated-safe'
    // The export boundary applies unsupportedPayloadPolicy (resolveBlockingExportDisposition);
    // diagnostic masks in place (length-preserving) — protected, not exposed.
    const unsupportedPolicy = input.unsupportedPayloadPolicy ?? policyFromLevel(preset).unsupportedPayloadPolicy
    if (unsupportedPolicy === 'mask-in-place') return 'protected-export-no-full-analysis'
    if (status === 'heuristic') return 'protected-export-no-full-analysis'
    if (preset === 'diagnostic') return 'recognized-risk-diagnostic'
    return 'unsupported-preserved'
  }

  if (status === 'truncated') return 'recognized-truncated-safe'
  if (status === 'covered') return 'recognized-and-protected'
  return 'unsupported-preserved'
}

function userVerdictLabel(verdict: UserCoverageVerdict): string {
  return cs.pcap.coverageUx.verdict[verdict]
}

function technicalSourceLabel(kind: CoverageLayerKind): string {
  switch (kind) {
    case 'both':
      return cs.pcap.inspector.coverageSourceBoth
    case 'sanitizer':
      return cs.pcap.inspector.coverageSourceSanitizer
    case 'structural':
      return cs.pcap.inspector.coverageSourceStructural
    default:
      return '—'
  }
}

function exportActionLabel(action: SpanExportAction): string {
  return cs.pcap.coverageUx.exportAction[action]
}

function protectedSpan(status: CoverageStatus): boolean {
  // T64 — heuristic is boundary-masked; do not count the producer status as protected content.
  return status === 'covered' || status === 'redacted' || status === 'truncated'
}

export function buildPlanRevision(input: {
  readonly generationId: string
  readonly mappingRevision: number
  readonly profileHash: string
  readonly planPacketCount: number
}): string {
  return `${input.generationId}:${input.mappingRevision}:${input.profileHash}:${input.planPacketCount}`
}

function buildSummary(input: {
  readonly statuses: PcapSessionStatusSnapshot
  readonly policy: SanitizationPolicy
  readonly plan: PcapPlanSnapshot
  readonly sanitizerCoverage?: readonly LayerCoverage[]
}): PcapCoverageSummary {
  const { statuses, policy, plan } = input
  const canExport =
    statuses.compatibility !== 'blocked' && statuses.anonymization !== 'blocked'
  const mediaUnsafe = isPreserveUnsafeMediaPolicy(policy.mediaPolicy)
  const fingerprintNormalized =
    policy.networkFingerprint.ttl === 'normalize'
    && policy.networkFingerprint.tcpWindow === 'normalize'
    && policy.networkFingerprint.flowLabel === 'normalize'
  // Step 7/9: diagnostic mapped fingerprints + preserve-for-diagnostics residuals
  // are intentional and must not force unsafe-export confirmation.
  const fingerprintDiagnosticOk =
    policy.networkFingerprint.ipv4Id === 'map'
    && policy.networkFingerprint.tcpSeq === 'map'
    && (policy.networkFingerprint.flowLabel === 'map'
      || policy.networkFingerprint.flowLabel === 'normalize')
    && policy.networkFingerprint.ttl === 'preserve-for-diagnostics'
    && policy.networkFingerprint.tcpWindow === 'preserve-for-diagnostics'
  const fingerprintOkForExport = fingerprintNormalized || fingerprintDiagnosticOk
  const exportLooksSafe =
    canExport
    && statuses.anonymization === 'covered'
    && !mediaUnsafe
    && fingerprintOkForExport

  let primaryAction: PrimaryExportAction = 'export-safe'
  if (!canExport) primaryAction = 'blocked'
  else if (mediaUnsafe || !fingerprintOkForExport || statuses.anonymization === 'exposed') {
    primaryAction = 'confirm-exposed'
  }
  else if (statuses.integrity === 'unverifiable' || statuses.unsupportedCount > 0) {
    primaryAction = policy.preset === 'high-privacy' ? 'export-safe' : 'inspect'
  }

  const reasons: string[] = []
  if (statuses.anonymization === 'blocked' || statuses.compatibility === 'blocked') {
    reasons.push(cs.pcap.coverageUx.reasonBlocked)
  } else if (mediaUnsafe) {
    reasons.push(cs.pcap.coverageUx.reasonUnsafeMedia)
  } else if (!fingerprintOkForExport) {
    reasons.push(cs.pcap.coverageUx.reasonExposed)
  } else if (statuses.anonymization === 'exposed') {
    reasons.push(cs.pcap.coverageUx.reasonExposed)
  }
  if (statuses.truncatedCount > 0) {
    reasons.push(cs.pcap.coverageUx.reasonTruncated.replace('{n}', String(statuses.truncatedCount)))
  }
  if (statuses.unsupportedCount > 0) {
    reasons.push(
      cs.pcap.coverageUx.reasonUnsupported.replace('{n}', String(statuses.unsupportedCount)),
    )
  }
  if (statuses.issueCount > 0 && reasons.length < 3) {
    reasons.push(cs.pcap.coverageUx.reasonIssues.replace('{n}', String(statuses.issueCount)))
  }

  const primaryVerdict =
    statuses.anonymization === 'blocked'
      ? cs.pcap.coverageUx.verdictBlocked
      : statuses.anonymization === 'exposed'
        ? cs.pcap.coverageUx.verdictExposed
        : cs.pcap.coverageUx.verdictSafe

  const anonymizationLabel =
    statuses.anonymization === 'covered'
      ? cs.pcap.status.anonCovered
      : statuses.anonymization === 'exposed'
        ? cs.pcap.status.anonExposed
        : cs.pcap.status.anonBlocked

  const integrityLabel =
    statuses.integrity === 'ok'
      ? cs.pcap.status.integOk
      : statuses.integrity === 'warnings'
        ? cs.pcap.status.integWarnings.replace('{n}', String(statuses.issueCount))
        : cs.pcap.status.integUnverifiable

  const compatibilityLabel =
    statuses.compatibility === 'valid'
      ? cs.pcap.status.compatValid
      : statuses.compatibility === 'valid-with-drops'
        ? cs.pcap.status.compatDrops.replace('{n}', String(statuses.droppedCount))
        : cs.pcap.status.compatBlocked

  const totals = plan.changeCategoryTotals
  const removedCount =
    (totals?.mapped ?? 0)
    + (totals?.redacted ?? 0)
    + (totals?.['masked-content'] ?? 0)
    + statuses.changedCount
  const keptCount =
    (totals?.['preserved-for-diagnostics'] ?? 0)
    + (totals?.['preserved-encrypted'] ?? 0)
    + 1 // timing/lengths/graph always present as intentional residual
  const blockedCount =
    (totals?.blocked ?? 0)
    + (statuses.anonymization === 'blocked' || statuses.compatibility === 'blocked' ? 1 : 0)

  const preExportSummaries: PcapPreExportSummaryBucket[] = [
    {
      id: 'removed',
      title: cs.pcap.coverageUx.summaryRemovedTitle,
      body: cs.pcap.coverageUx.summaryRemovedBody,
      itemCount: Math.max(removedCount, statuses.changedCount),
    },
    {
      id: 'kept',
      title: cs.pcap.coverageUx.summaryKeptTitle,
      body: cs.pcap.coverageUx.summaryKeptBody,
      itemCount: keptCount,
    },
    {
      id: 'blocked',
      title: cs.pcap.coverageUx.summaryBlockedTitle,
      body:
        blockedCount > 0
          ? cs.pcap.coverageUx.summaryBlockedBody
          : cs.pcap.coverageUx.summaryBlockedEmpty,
      itemCount: blockedCount,
    },
  ]

  // Sanitizer spans (weighted rollup on the R10 packed path) — without them the preview would
  // see zero exposed regions and show a green gate for preserved-unsafe content.
  const privacy = buildPrivacyReport({
    plan,
    policy,
    coverage: input.sanitizerCoverage,
    unsafeExportAcknowledged: false,
  })
  const coverageSummary = summarizeSanitizationCoverage({
    plan,
    coverage: input.sanitizerCoverage,
    unsupportedLayers: statuses.unsupportedCount,
    policy,
  })
  const previewChecks = buildGateChecksFromCoverage({
    coverage: coverageSummary,
    leakHits: 0,
    verificationFatalErrors:
      statuses.anonymization === 'blocked' || statuses.compatibility === 'blocked' ? 1 : 0,
    profile: policy.preset,
    diagnosticInvariantOk:
      policy.preset === 'diagnostic'
        ? statuses.droppedCount === 0
        : undefined,
  })
  const gateOutcome = resolveExportGate({
    profile: policy.preset,
    checks: previewChecks,
    exportBlocked: statuses.anonymization === 'blocked' || statuses.compatibility === 'blocked',
  })
  // UI canExport stays plan/status based; report gate at export still enforces full checks.
  // Preview badge: fail-closed unsupported → AI_READY_WITH_GAPS (not NOT_AI_READY).
  // The session statuses already flagged readable content left in the output ('exposed');
  // the gate preview must never be greener than that.
  const gateBadge: PcapCoverageSummary['gateBadge'] =
    statuses.anonymization !== 'covered' && gateOutcome.gate === 'AI_READY'
      ? 'NOT_AI_READY'
      : gateOutcome.gate
  const gateBadgeLabel =
    gateBadge === 'AI_READY'
      ? cs.pcap.coverageUx.gateAiReady
      : gateBadge === 'AI_READY_WITH_GAPS'
        ? cs.pcap.coverageUx.gateAiReadyWithGaps
        : cs.pcap.coverageUx.gateNotAiReady

  const diagnosticResidualRisk = buildDiagnosticResidualRisk({
    profile: policy.preset,
    privacy,
  })
  const residualRiskLabels: string[] = []
  if (diagnosticResidualRisk.graph) residualRiskLabels.push(cs.pcap.coverageUx.residualGraph)
  if (diagnosticResidualRisk.timing) residualRiskLabels.push(cs.pcap.coverageUx.residualTiming)
  if (diagnosticResidualRisk.topology) residualRiskLabels.push(cs.pcap.coverageUx.residualTopology)
  if (diagnosticResidualRisk.fingerprint) residualRiskLabels.push(cs.pcap.coverageUx.residualFingerprint)

  return {
    canExport,
    exportLooksSafe,
    primaryVerdict,
    primaryAction,
    primaryActionLabel: cs.pcap.coverageUx.primaryAction[primaryAction],
    reasons: reasons.slice(0, 3),
    changedCount: statuses.changedCount,
    removedCount: statuses.truncatedCount + statuses.droppedCount,
    attentionCount: statuses.unsupportedCount + statuses.reassemblyCount + statuses.issueCount,
    anonymization: statuses.anonymization,
    integrity: statuses.integrity,
    compatibility: statuses.compatibility,
    anonymizationLabel,
    integrityLabel,
    compatibilityLabel,
    preExportSummaries,
    residualNote: cs.pcap.coverageUx.residualNote,
    gateBadge,
    gateBadgeLabel,
    diagnosticResidualRisk,
    residualRiskLabels,
  }
}

export function buildPcapCoverageViewModel(input: {
  /** Flattened sanitizer coverage for gate bookkeeping (see `sanitizerCoverageForExport`). */
  readonly sanitizerCoverage?: readonly LayerCoverage[]
  readonly unifiedCoverage: UnifiedCoverageModel
  readonly policy: SanitizationPolicy
  readonly plan: PcapPlanSnapshot
  readonly statuses: PcapSessionStatusSnapshot
  readonly generationId: string
  readonly mappingRevision: number
  readonly profileHash: string
}): PcapCoverageViewModel {
  const planRevision = buildPlanRevision({
    generationId: input.generationId,
    mappingRevision: input.mappingRevision,
    profileHash: input.profileHash,
    planPacketCount: input.plan.packets.length,
  })

  const protocols: PcapProtocolCoverageRow[] = input.unifiedCoverage.byProtocol.map((p) => {
    const layerKind = layerKindFromCounts(p.structuralSpanCount, p.sanitizerSpanCount)
    const userVerdict = userVerdictForProtocol({
      layerKind,
      dominantStatus: p.dominantStatus,
      truncateUnsupported: input.policy.truncateUnsupported,
      preset: input.policy.preset,
      unsupportedPayloadPolicy: input.policy.unsupportedPayloadPolicy,
    })
    let ui = coverageStatusToUiStatus(p.dominantStatus)
    if (userVerdict === 'recognized-risk-diagnostic' || userVerdict === 'unsupported-preserved') {
      ui = dominantUiStatus(ui, 'exposed')
    }
    if (userVerdict === 'blocking' || p.dominantStatus === 'malformed') {
      ui = dominantUiStatus(ui, 'blocked')
    }

    // Protected ≈ packets where sanitizer acted, or truncated/covered structural spans.
    const protectedPacketCount = Math.min(
      p.packetCount,
      Math.max(
        p.sanitizerSpanCount > 0
          ? Math.ceil((p.sanitizerSpanCount / Math.max(1, p.spanCount)) * p.packetCount)
          : 0,
        protectedSpan(p.dominantStatus) ? p.packetCount : 0,
      ),
    )

    const family = familyForProtocol(p.protocol)
    return {
      protocol: p.protocol,
      familyId: family.familyId,
      familyLabel: protocolFamilyLabel(family),
      probableIdentification: family.probable,
      recognizedPacketCount: p.packetCount,
      familyPacketCount: p.familyPacketCount,
      protectedPacketCount,
      layerKind,
      dominantStatus: p.dominantStatus,
      dominantUiStatus: ui,
      userVerdict,
      userVerdictLabel: userVerdictLabel(userVerdict),
      technicalSourceLabel: technicalSourceLabel(layerKind),
      unsupportedCount: p.unsupportedCount,
      filterProtocol: p.protocol,
    }
  })

  const summary = buildSummary({
    sanitizerCoverage: input.sanitizerCoverage,
    statuses: input.statuses,
    policy: input.policy,
    plan: input.plan,
  })

  return {
    planRevision,
    mappingRevision: input.mappingRevision,
    generationId: input.generationId,
    summary,
    protocols,
    spansForPacket(packetIndex: number): readonly PcapSpanCoverageRow[] {
      const spans = input.unifiedCoverage.perPacket[packetIndex] ?? []
      return spans.map((span) => toSpanRow(span, input.policy))
    },
  }
}

function toSpanRow(span: UnifiedLayerCoverage, policy: SanitizationPolicy): PcapSpanCoverageRow {
  const blocking =
    span.status === 'malformed' ||
    (span.status === 'unsupported' && !policy.truncateUnsupported && policy.preset !== 'high-privacy')
  const action = spanExportAction(span.status, { blocking, protocol: span.protocol })
  const needsAttention =
    span.status === 'unsupported' ||
    span.status === 'requires-reassembly' ||
    span.status === 'malformed' ||
    span.status === 'heuristic'
  const layerKind: CoverageLayerKind =
    span.source === 'sanitizer' ? 'sanitizer' : 'structural'
  return {
    protocol: span.protocol,
    offset: span.offset,
    length: span.length,
    status: span.status,
    statusLabel: coverageStatusLabel(span.status),
    exportAction: action,
    exportActionLabel: exportActionLabel(action),
    layerKind,
    technicalSource: span.source,
    needsAttention,
  }
}

/** Merge span statuses for a packet into one dominant UI status (shared matrix). */
export function dominantUiStatusForSpans(
  spans: readonly UnifiedLayerCoverage[],
): DominantUiStatus | null {
  if (spans.length === 0) return null
  let worst: DominantUiStatus = coverageStatusToUiStatus(spans[0]!.status)
  for (let i = 1; i < spans.length; i++) {
    worst = dominantUiStatus(worst, coverageStatusToUiStatus(spans[i]!.status))
  }
  return worst
}

