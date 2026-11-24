/**
 * PCAP export report — safe summary without original entity values (Stage 13 / step 8).
 * CF-15 embeds a privacy report derived from the immutable plan (no original values).
 */

import type { PcapPlanSnapshot } from './planSnapshot'
import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel'
import { CaptureFormat } from '../domain/types'
import type { ChecksumReport } from '../checksums/types'
import { PCAP_ENGINE_VERSION } from './planSnapshot'
import {
  emptyDispositionAggregate,
  type DispositionLedgerAggregate,
} from './dispositionLedger'
import type { UnifiedProtocolSummary } from '../coverage/types'
import {
  buildAnonymizationOutcomeForExport,
  type AnonymizationOutcomeReportSection,
} from '../coverage/anonymizationOutcome'
import type { ExportValidationOutcome } from './incremental/baselineCompare'
import type { PcapPrivacyReport } from '../privacy/privacyReport'
import {
  emptyPlanChangeCounts,
  type PlanChangeCounts,
  type PlanDispositionReason,
} from '../plan/planDisposition'
import type {
  DiagnosticResidualRisk,
  ExportGateChecks,
  ExportValidityLayers,
  GateResult,
  LeakScanFinding,
  LeakScanOriginal,
  SanitizationCoverageSummary,
} from '../trust'
import {
  buildDiagnosticResidualRisk,
  buildGateChecksFromCoverage,
  buildValidityLayers,
  emptyLeakScanResult,
  resolveCryptographicIntegrity,
  resolveExportGate,
  scanArtifactForOriginalLeaks,
  summarizeSanitizationCoverage,
} from '../trust'
import type { LayerCoverage } from '../sanitize/types'
import {
  summarizeTlsHandling,
  type TlsHandlingSummary,
} from '../sanitize/tlsBranches'

export interface PcapExportLengthChangeSummary {
  readonly truncatedPacketCount: number
  /** Sum of (exportedCapturedLength - originalCapturedLength); typically 0 for diagnostic. */
  readonly capturedLengthDeltaBytes: number
  /** Sum of (exportedWireLength - originalWireLength); typically 0 for diagnostic. */
  readonly wireLengthDeltaBytes: number
}

export interface PcapExportDiagnosticInvariant {
  readonly enforced: boolean
  readonly ok: boolean
  readonly droppedPackets: number
  readonly packetCountDelta: number
}

export interface PcapExportReport {
  readonly format: 'rnd-log-anonymizer-pcap-report'
  /**
   * Schema 8 (T10): anonymizationOutcome (families, incidents, masked packet ranges).
   * Schema 7 (T08): three-state gate AI_READY / AI_READY_WITH_GAPS / NOT_AI_READY;
   * sanitization includes failClosedRegions / exposedRegions / incidentCount.
   * Schema 6 added coverage + leak + residual risk. Never conflates profile with gate.
   */
  readonly schemaVersion: 8
  /** T10 — machine-readable outcome for UI/AI agents (no original values). */
  readonly anonymizationOutcome: AnonymizationOutcomeReportSection
  readonly engineVersion: string
  /** Profile: diagnostic | high-privacy — not a gate value. */
  readonly pcapLevel: PcapAnonymizationLevel
  /** @deprecated Prefer pcapLevel — derived id `pcap-{level}`. */
  readonly profileId: string
  readonly profileHash: string
  readonly policyHash?: string
  readonly captureFormat: 'pcap' | 'pcapng'
  /**
   * Safe export label only (never the original capture basename).
   * Actual download name may differ in the UI.
   */
  readonly exportedFileName: string
  readonly inputPacketCount: number
  readonly outputPacketCount: number
  readonly packetCountDelta: number
  /** @deprecated Prefer outputPacketCount — kept for older UI readers. */
  readonly packetCount: number
  readonly droppedPackets: number
  readonly dropsByReason: Readonly<Partial<Record<PlanDispositionReason, number>>>
  readonly dropsByProtocol: Readonly<Record<string, number>>
  readonly changedPackets: number
  readonly truncatedPayloads: number
  readonly lengthChanges: PcapExportLengthChangeSummary
  readonly changeCategoryTotals: PlanChangeCounts
  readonly maskedByteCount: number
  /** T62 — disposition ledger aggregates (no per-byte ranges / no originals). */
  readonly dispositionLedger: DispositionLedgerAggregate
  readonly unsupportedLayers: number
  readonly protocolCoverage: readonly UnifiedProtocolSummary[]
  readonly checksum: ChecksumReport['counts']
  /** Step 6 — pre-sanitize checksum classification sidecard. */
  readonly checksumOriginalStates?: ChecksumReport['originalStateCounts']
  /**
   * Step 10 — TLS handshake branches observed (tls-1.2 / tls-1.3 / ech).
   * Safe labels only — no hostnames or cert subjects.
   */
  readonly tlsHandling?: TlsHandlingSummary
  readonly validation: {
    readonly valid: boolean
    readonly issueCount: number
    readonly newBlockingIssueCount: number
    readonly preservedBaselineIssueCount: number
  }
  readonly generationId: string
  readonly diagnosticInvariant?: PcapExportDiagnosticInvariant
  /** CF-15 — threat residuals and unsafe-ack; omitted only in legacy unit fixtures. */
  readonly privacy?: PcapPrivacyReport
  /**
   * Whether a recovery sidecar was created for this export.
   * Must not include hashes, recoveryId, KDF params, passphrase, or original filename.
   */
  readonly recoveryCreated?: boolean
  /** Four validity layers (not a single "wire-valid" flag). */
  readonly validity: ExportValidityLayers
  /**
   * Gate: AI_READY | AI_READY_WITH_GAPS | NOT_AI_READY.
   * High-privacy may carry AI_READY (gate describes output, not level). Never a profile name.
   * Legacy readers: SAFE_FOR_AI ≈ AI_READY, SANITIZATION_INCOMPLETE ≈ NOT_AI_READY.
   */
  readonly gate: GateResult
  /** Whether the sanitized artifact may leave the trust boundary. */
  readonly exportAllowed: boolean
  /** Convenience: gate === AI_READY. */
  readonly safeForAi: boolean
  /** Convenience: gate === AI_READY_WITH_GAPS. */
  readonly aiReadyWithGaps: boolean
  /** @deprecated Prefer `gate`. */
  readonly gateBadge: GateResult
  /** Step 5 — measurable MAP/MASK / unverified / metadata coverage. */
  readonly sanitization: SanitizationCoverageSummary
  /** Step 5 — structured gate inputs (auditability). */
  readonly gateChecks: ExportGateChecks
  /**
   * Step 5 — leak findings without original values.
   * Shape: `{ category, hits, packetNumbers }`.
   */
  readonly leakFindings: readonly LeakScanFinding[]
  /** Step 5 — intentional residual risk axes (always shown for diagnostic). */
  readonly diagnosticResidualRisk: DiagnosticResidualRisk
}

function safeExportedLabel(captureFormat: 'pcap' | 'pcapng'): string {
  return captureFormat === 'pcapng' ? 'capture.anonymized.pcapng' : 'capture.anonymized.pcap'
}

function lengthChangesFromPlan(plan: PcapPlanSnapshot): PcapExportLengthChangeSummary {
  let truncatedPacketCount = 0
  let capturedLengthDeltaBytes = 0
  let wireLengthDeltaBytes = 0
  for (const p of plan.packets) {
    if (p.drop) continue
    const outCaptured = p.truncatedLength ?? p.originalCapturedLength
    const outWire = p.truncatedLength ?? p.originalLength
    if (p.truncatedLength !== undefined) truncatedPacketCount++
    capturedLengthDeltaBytes += outCaptured - p.originalCapturedLength
    wireLengthDeltaBytes += outWire - p.originalLength
  }
  return { truncatedPacketCount, capturedLengthDeltaBytes, wireLengthDeltaBytes }
}

export function buildExportReport(input: {
  plan: PcapPlanSnapshot
  /** Ignored for report content — step 8 forbids embedding original-derived names. */
  exportedFileName: string
  changedPackets: number
  truncatedPayloads: number
  unsupportedLayers: number
  protocolCoverage: readonly UnifiedProtocolSummary[]
  checksum: ChecksumReport
  validation: ExportValidationOutcome
  privacy?: PcapPrivacyReport
  /** When set, enforce diagnostic zero-drop / zero packet-count delta. */
  diagnosticPreset?: boolean
  /** Safe recovery flag only. */
  recoveryCreated?: boolean
  /** Override cryptographic_integrity when known (default UNKNOWN until steps 6–8). */
  cryptographicIntegrity?: ExportValidityLayers['cryptographic_integrity']
  /** Flattened discovery/sanitizer coverage for gate bookkeeping. */
  coverage?: readonly LayerCoverage[]
  /** Safe sanitizer issue tokens (e.g. tls-branch:ech) — no original identities. */
  issues?: readonly string[]
  /** PCAPNG metadata blocks dropped on ingest (DSB/NRB/ISB). */
  droppedMetadataBlocks?: number
  dsbDropped?: number
  nrbDropped?: number
  /**
   * Original entity canaries held only in memory for leak scan against report JSON.
   * Never written into the report.
   */
  leakOriginals?: readonly LeakScanOriginal[]
  /** Optional precomputed anonymized bytes for leak scan (in addition to report JSON). */
  anonymizedBytes?: Uint8Array
}): PcapExportReport {
  const inputPacketCount = input.plan.packets.length
  const droppedPackets = input.plan.droppedPacketNumbers.length
  const outputPacketCount = inputPacketCount - droppedPackets
  const packetCountDelta = outputPacketCount - inputPacketCount
  const captureFormat = input.plan.format === CaptureFormat.Pcapng ? 'pcapng' : 'pcap'
  const changeCategoryTotals = input.plan.changeCategoryTotals ?? emptyPlanChangeCounts()
  const maskedByteCount = input.plan.maskedByteCount ?? 0
  const dropsByReason = input.plan.dropsByReason ?? {}
  const dropsByProtocol = input.plan.dropsByProtocol ?? {}

  let diagnosticInvariant: PcapExportDiagnosticInvariant | undefined
  if (input.diagnosticPreset) {
    const ok = droppedPackets === 0 && packetCountDelta === 0
    diagnosticInvariant = {
      enforced: true,
      ok,
      droppedPackets,
      packetCountDelta,
    }
    if (!ok) {
      throw new Error(
        `Diagnostic export invariant violated: droppedPackets=${droppedPackets} packetCountDelta=${packetCountDelta}`,
      )
    }
  }

  const newBlockingIssueCount = input.validation.newBlockingIssues.length
  const cryptographicIntegrity =
    input.cryptographicIntegrity
    ?? resolveCryptographicIntegrity({
      coverage: input.coverage,
      issues: input.issues,
    })
  const validity = buildValidityLayers({
    validationValid: input.validation.validationValid,
    newBlockingIssueCount,
    checksumCounts: input.checksum.counts,
    unsupportedLayers: input.unsupportedLayers,
    cryptographicIntegrity,
  })

  const sanitization = summarizeSanitizationCoverage({
    plan: input.plan,
    coverage: input.coverage,
    unsupportedLayers: input.unsupportedLayers,
    droppedMetadataBlocks: input.droppedMetadataBlocks,
    dsbDropped: input.dsbDropped,
    nrbDropped: input.nrbDropped,
    cryptoInvalidatedCount:
      validity.cryptographic_integrity === 'MODIFIED' ? 1 : 0,
  })

  // Leak scan runs against a provisional artifact string (report fields without leak section).
  // Originals stay in memory only.
  const leakProbe = JSON.stringify({
    format: 'rnd-log-anonymizer-pcap-report',
    pcapLevel: input.plan.pcapLevel,
    changeCategoryTotals,
    maskedByteCount,
    generationId: input.plan.generationId,
  })
  let leakScan = emptyLeakScanResult()
  if (input.leakOriginals && input.leakOriginals.length > 0) {
    leakScan = scanArtifactForOriginalLeaks({
      artifact: leakProbe,
      originals: input.leakOriginals,
    })
    if (input.anonymizedBytes && input.anonymizedBytes.byteLength > 0) {
      const bytesScan = scanArtifactForOriginalLeaks({
        artifact: input.anonymizedBytes,
        originals: input.leakOriginals,
      })
      // Merge: sum hits, union packet numbers (export-safe).
      const merged = new Map<string, { hits: number; packets: Set<number> }>()
      for (const f of [...leakScan.findings, ...bytesScan.findings]) {
        const cur = merged.get(f.category) ?? { hits: 0, packets: new Set<number>() }
        cur.hits += f.hits
        for (const n of f.packetNumbers) cur.packets.add(n)
        merged.set(f.category, cur)
      }
      leakScan = {
        findings: [...merged.entries()]
          .map(([category, b]) => ({
            category: category as LeakScanFinding['category'],
            hits: b.hits,
            packetNumbers: [...b.packets].sort((a, c) => a - c).slice(0, 32),
          }))
          .sort((a, b) => a.category.localeCompare(b.category)),
        leakHits: [...merged.values()].reduce((n, b) => n + b.hits, 0),
      }
    }
  }

  const privacyUnsafe =
    input.privacy?.requiresUnsafeConfirmation === true
    && input.privacy.unsafeExportAcknowledged !== true

  const verificationFatalErrors =
    (!input.validation.validationValid ? 1 : 0)
    + newBlockingIssueCount
    + (privacyUnsafe ? 1 : 0)

  const gateChecks = buildGateChecksFromCoverage({
    coverage: sanitization,
    leakHits: leakScan.leakHits,
    verificationFatalErrors,
    profile: input.plan.pcapLevel,
    diagnosticInvariantOk: diagnosticInvariant ? diagnosticInvariant.ok : undefined,
  })

  const gate = resolveExportGate({
    profile: input.plan.pcapLevel,
    checks: gateChecks,
    exportBlocked: !input.validation.validationValid || newBlockingIssueCount > 0,
    unsafeExportAcknowledged: input.privacy?.unsafeExportAcknowledged === true,
  })

  const diagnosticResidualRisk = buildDiagnosticResidualRisk({
    profile: input.plan.pcapLevel,
    privacy: input.privacy,
  })

  const anonymizationOutcome = buildAnonymizationOutcomeForExport({
    protocolCoverage: input.protocolCoverage,
    gate: gate.gate,
    plan: input.plan,
    incidents: input.plan.incidents,
    preset: input.plan.pcapLevel === 'high-privacy' ? 'high-privacy' : 'diagnostic',
  })

  return {
    format: 'rnd-log-anonymizer-pcap-report',
    schemaVersion: 8,
    engineVersion: PCAP_ENGINE_VERSION,
    pcapLevel: input.plan.pcapLevel,
    profileId: input.plan.profileId,
    profileHash: input.plan.profileHash,
    policyHash: input.plan.policyHash || input.plan.profileHash,
    captureFormat,
    exportedFileName: safeExportedLabel(captureFormat),
    inputPacketCount,
    outputPacketCount,
    packetCountDelta,
    packetCount: outputPacketCount,
    droppedPackets,
    dropsByReason,
    dropsByProtocol,
    changedPackets: input.changedPackets,
    truncatedPayloads: input.truncatedPayloads,
    lengthChanges: lengthChangesFromPlan(input.plan),
    changeCategoryTotals,
    maskedByteCount,
    dispositionLedger: input.plan.dispositionLedger ?? emptyDispositionAggregate(),
    unsupportedLayers: input.unsupportedLayers,
    protocolCoverage: input.protocolCoverage,
    checksum: input.checksum.counts,
    ...(input.checksum.originalStateCounts
      ? { checksumOriginalStates: input.checksum.originalStateCounts }
      : {}),
    ...(() => {
      const tlsHandling = summarizeTlsHandling({
        coverage: input.coverage,
        protocolCoverage: input.protocolCoverage,
        issues: input.issues,
      })
      return tlsHandling.branches.length > 0 ? { tlsHandling } : {}
    })(),
    validation: {
      valid: input.validation.validationValid,
      issueCount: input.validation.validationIssueCount,
      newBlockingIssueCount,
      preservedBaselineIssueCount: input.validation.preservedBaselineIssues.length,
    },
    generationId: input.plan.generationId,
    ...(diagnosticInvariant ? { diagnosticInvariant } : {}),
    ...(input.privacy ? { privacy: input.privacy } : {}),
    ...(input.recoveryCreated === true ? { recoveryCreated: true } : {}),
    validity,
    gate: gate.gate,
    exportAllowed: gate.exportAllowed,
    safeForAi: gate.safeForAi,
    aiReadyWithGaps: gate.aiReadyWithGaps,
    gateBadge: gate.gate,
    sanitization,
    gateChecks,
    leakFindings: leakScan.findings,
    diagnosticResidualRisk,
    anonymizationOutcome,
  }
}

export function reportFileName(exportFileName: string): string {
  if (exportFileName.endsWith('.pcapng')) {
    return exportFileName.replace(/\.pcapng$/, '.report.json')
  }
  if (exportFileName.endsWith('.pcap')) {
    return exportFileName.replace(/\.pcap$/, '.report.json')
  }
  return `${exportFileName}.report.json`
}

/**
 * Reject reports / AI manifests that accidentally embed correlatable identifiers.
 * Step 8 canary: IP, MAC, hostname-like FQDNs, phones, SIP URIs, credentials, paths, hashes.
 */
export function assertReportHasNoOriginalIdentifiers(reportJson: string): void {
  const forbidden: Array<{ name: string; pattern: RegExp }> = [
    { name: 'ipv4', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/ },
    { name: 'mac', pattern: /(?:[0-9a-f]{2}:){5}[0-9a-f]{2}/i },
    { name: 'sip-uri', pattern: /\bsips?:[^\s"']+/i },
    { name: 'email', pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
    { name: 'phone', pattern: /\btel:\+?\d{6,}\b/i },
    { name: 'credential', pattern: /\b(?:password|passwd|authorization|bearer\s+[a-z0-9._~+/=-]{8,})\b/i },
    { name: 'abs-path', pattern: /(?:\/Users\/|\/home\/|[A-Za-z]:\\)/ },
    { name: 'sourceFileName-field', pattern: /"sourceFileName"\s*:/ },
    { name: 'timestampAnchorSeed-field', pattern: /"timestampAnchorSeed"\s*:/ },
    { name: 'sha256-hex', pattern: /\b[a-f0-9]{64}\b/i },
    { name: 'recoveryId-field', pattern: /"recoveryId"\s*:/ },
    { name: 'passphrase-field', pattern: /"passphrase"\s*:/ },
    { name: 'pbkdf2-field', pattern: /"pbkdf2(?:Iterations|Salt)"\s*:/i },
    { name: 'originalValue-field', pattern: /"originalValue"\s*:/ },
    { name: 'hostname-field', pattern: /"hostname"\s*:/ },
  ]
  for (const { name, pattern } of forbidden) {
    if (pattern.test(reportJson)) {
      throw new Error(`Export artifact must not contain correlatable identifier (${name})`)
    }
  }
}

/** Optional seed denylist for acceptance tests (original filename, hostnames, etc.). */
export function assertArtifactHasNoCanaryLeaks(
  json: string,
  canaries: readonly string[],
): void {
  assertReportHasNoOriginalIdentifiers(json)
  const lower = json.toLowerCase()
  for (const canary of canaries) {
    if (!canary) continue
    if (lower.includes(canary.toLowerCase())) {
      throw new Error(`Export artifact leaked canary value: ${canary}`)
    }
  }
}
