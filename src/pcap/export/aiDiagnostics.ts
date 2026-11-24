/**
 * Step 8 — optional AI diagnostics sidecar derived only from anonymized plan/output.
 * Never includes mapping bundles, original entities, filenames, or correlatable hashes.
 * Schema 5 — T10 anonymizationOutcome + T08 three-state gate (no originals).
 */

import { CaptureFormat } from '../domain/types'
import type { UnifiedProtocolSummary } from '../coverage/types'
import {
  buildAnonymizationOutcomeForExport,
  type AnonymizationOutcomeReportSection,
} from '../coverage/anonymizationOutcome'
import {
  emptyPlanChangeCounts,
  type PlanChangeCounts,
  type PlanDispositionReason,
} from '../plan/planDisposition'
import { PCAP_ENGINE_VERSION, type PcapPlanSnapshot } from './planSnapshot'
import type {
  DiagnosticResidualRisk,
  ExportValidityLayers,
  GateResult,
  LeakScanFinding,
} from '../trust'
import {
  buildDiagnosticResidualRisk,
  buildValidityLayers,
  normalizeGateResult,
  resolveExportGate,
} from '../trust'
import type { PcapPrivacyReport } from '../privacy/privacyReport'

export interface AiDiagnosticsPacketSummary {
  readonly packetNumber: number
  readonly dispositionReason: PlanDispositionReason
  readonly protocols: readonly string[]
  readonly changeCounts: PlanChangeCounts
  readonly maskedByteCount: number
}

export interface AiDiagnosticsProtocolSummary {
  readonly protocol: string
  readonly packetCount: number
  readonly dominantStatus: string
}

export interface PcapAiDiagnosticsManifest {
  readonly format: 'rnd-log-anonymizer-pcap-ai-diagnostics'
  /** Schema 5 — T10 anonymizationOutcome + T08 three-state gate (no originals). */
  readonly schemaVersion: 5
  readonly engineVersion: string
  readonly pcapLevel?: PcapPlanSnapshot['pcapLevel']
  /** @deprecated Prefer pcapLevel / policyHash. */
  readonly profileId: string
  readonly policyHash?: string
  readonly captureFormat: 'pcap' | 'pcapng'
  readonly inputPacketCount: number
  readonly outputPacketCount: number
  readonly droppedPacketCount: number
  readonly changeCategoryTotals: PlanChangeCounts
  readonly maskedByteCount: number
  readonly protocolSummaries: readonly AiDiagnosticsProtocolSummary[]
  readonly packetSummaries: readonly AiDiagnosticsPacketSummary[]
  readonly warnings: readonly string[]
  readonly aggregates: {
    readonly mappedSpanCount: number
    readonly redactedSpanCount: number
    readonly maskedContentSpanCount: number
    readonly preservedEncryptedSpanCount: number
    readonly preservedForDiagnosticsSpanCount: number
    /** Packets with truncated captured length relative to input record. */
    readonly truncatedPacketCount: number
  }
  readonly validity: ExportValidityLayers
  readonly gate: GateResult
  readonly exportAllowed: boolean
  readonly safeForAi: boolean
  readonly aiReadyWithGaps: boolean
  /** @deprecated Prefer `gate`. */
  readonly gateBadge: GateResult
  readonly diagnosticResidualRisk: DiagnosticResidualRisk
  readonly leakFindings: readonly LeakScanFinding[]
  /** T10 — verdict, families, masked packet ranges (no originals). */
  readonly anonymizationOutcome: AnonymizationOutcomeReportSection
}

export function buildAiDiagnosticsManifest(input: {
  plan: PcapPlanSnapshot
  protocolCoverage?: readonly UnifiedProtocolSummary[]
  warnings?: readonly string[]
  unsupportedLayers?: number
  checksumCounts?: Readonly<Partial<Record<string, number>>>
  validationValid?: boolean
  newBlockingIssueCount?: number
  requiresUnsafeConfirmation?: boolean
  unsafeExportAcknowledged?: boolean
  /** Prefer copying gate/residual/leak from the companion sanitization report. */
  gate?: GateResult | null
  exportAllowed?: boolean
  safeForAi?: boolean
  aiReadyWithGaps?: boolean
  diagnosticResidualRisk?: DiagnosticResidualRisk
  leakFindings?: readonly LeakScanFinding[]
  privacy?: Pick<PcapPrivacyReport, 'residualRisks' | 'preservesExactTimestampDeltas' | 'networkFingerprintNormalized'>
}): PcapAiDiagnosticsManifest {
  const plan = input.plan
  const inputPacketCount = plan.packets.length
  const outputPacketCount = inputPacketCount - plan.droppedPacketNumbers.length
  const totals = plan.changeCategoryTotals ?? emptyPlanChangeCounts()

  const protocolSummaries: AiDiagnosticsProtocolSummary[] = (input.protocolCoverage ?? [])
    .filter((p) => p.packetCount > 0)
    .map((p) => ({
      protocol: p.protocol,
      packetCount: p.packetCount,
      dominantStatus: p.dominantStatus,
    }))

  const packetSummaries: AiDiagnosticsPacketSummary[] = plan.packets.map((p) => ({
    packetNumber: p.packetNumber,
    dispositionReason: p.dispositionReason ?? (p.drop ? 'user-requested-drop' : 'exported'),
    protocols: p.primaryProtocol ? [p.primaryProtocol] : [],
    changeCounts: p.changeCounts ?? emptyPlanChangeCounts(),
    maskedByteCount: p.maskedByteCount ?? 0,
  }))

  let truncatedPacketCount = 0
  for (const p of plan.packets) {
    if (p.truncatedLength !== undefined) truncatedPacketCount++
  }

  const warnings = [...(input.warnings ?? [])]
  if (plan.droppedPacketNumbers.length > 0) {
    warnings.push(`dropped-packets:${plan.droppedPacketNumbers.length}`)
  }

  const validationValid = input.validationValid !== false
  const newBlockingIssueCount = input.newBlockingIssueCount ?? 0
  const unsupportedLayers = input.unsupportedLayers ?? 0
  const validity = buildValidityLayers({
    validationValid,
    newBlockingIssueCount,
    checksumCounts: input.checksumCounts,
    unsupportedLayers,
  })
  const privacyUnsafe =
    input.requiresUnsafeConfirmation === true
    && input.unsafeExportAcknowledged !== true
  const normalizedInputGate = input.gate != null ? normalizeGateResult(input.gate) : null
  const resolvedGate =
    normalizedInputGate != null
      ? {
          gate: normalizedInputGate,
          exportAllowed:
            input.exportAllowed
            ?? (normalizedInputGate === 'AI_READY' || normalizedInputGate === 'AI_READY_WITH_GAPS'),
          safeForAi: input.safeForAi ?? normalizedInputGate === 'AI_READY',
          aiReadyWithGaps:
            input.aiReadyWithGaps ?? normalizedInputGate === 'AI_READY_WITH_GAPS',
        }
      : resolveExportGate({
          profile: plan.pcapLevel,
          sanitizationIncomplete: !validationValid || newBlockingIssueCount > 0 || privacyUnsafe,
          exportBlocked: !validationValid || newBlockingIssueCount > 0,
        })

  const diagnosticResidualRisk =
    input.diagnosticResidualRisk
    ?? buildDiagnosticResidualRisk({ profile: plan.pcapLevel, privacy: input.privacy })

  const gate = resolvedGate.gate ?? 'NOT_AI_READY'
  const anonymizationOutcome = buildAnonymizationOutcomeForExport({
    protocolCoverage: input.protocolCoverage ?? [],
    gate,
    plan,
    incidents: plan.incidents,
    preset: plan.pcapLevel === 'high-privacy' ? 'high-privacy' : 'diagnostic',
  })

  return {
    format: 'rnd-log-anonymizer-pcap-ai-diagnostics',
    schemaVersion: 5,
    engineVersion: PCAP_ENGINE_VERSION,
    pcapLevel: plan.pcapLevel,
    profileId: plan.profileId,
    policyHash: plan.policyHash || plan.profileHash,
    captureFormat: plan.format === CaptureFormat.Pcapng ? 'pcapng' : 'pcap',
    inputPacketCount,
    outputPacketCount,
    droppedPacketCount: plan.droppedPacketNumbers.length,
    changeCategoryTotals: totals,
    maskedByteCount: plan.maskedByteCount ?? 0,
    protocolSummaries,
    packetSummaries,
    warnings,
    aggregates: {
      mappedSpanCount: totals.mapped,
      redactedSpanCount: totals.redacted,
      maskedContentSpanCount: totals['masked-content'],
      preservedEncryptedSpanCount: totals['preserved-encrypted'],
      preservedForDiagnosticsSpanCount: totals['preserved-for-diagnostics'],
      truncatedPacketCount,
    },
    validity,
    gate,
    exportAllowed: resolvedGate.exportAllowed,
    safeForAi: resolvedGate.safeForAi,
    aiReadyWithGaps: resolvedGate.aiReadyWithGaps ?? false,
    gateBadge: gate,
    diagnosticResidualRisk,
    leakFindings: input.leakFindings ?? [],
    anonymizationOutcome,
  }
}

export function aiDiagnosticsFileName(exportFileName: string): string {
  if (exportFileName.endsWith('.pcapng')) {
    return exportFileName.replace(/\.pcapng$/, '.ai-diagnostics.json')
  }
  if (exportFileName.endsWith('.pcap')) {
    return exportFileName.replace(/\.pcap$/, '.ai-diagnostics.json')
  }
  return `${exportFileName}.ai-diagnostics.json`
}
