/**
 * Enterprise step 5 — coverage bookkeeping, leak scanner, gate + residual risk.
 */

import { describe, expect, it } from 'vitest'
import {
  buildDiagnosticResidualRisk,
  buildGateChecksFromCoverage,
  emptyLeakScanResult,
  mapEntityCategoryToLeak,
  resolveExportGate,
  scanArtifactForOriginalLeaks,
  summarizeSanitizationCoverage,
} from '../../../src/pcap/trust'
import { buildExportReport, assertReportHasNoOriginalIdentifiers } from '../../../src/pcap/export/report'
import { buildAiDiagnosticsManifest } from '../../../src/pcap/export/aiDiagnostics'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import type { PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import { emptyChecksumCounts } from '../../../src/pcap/checksums/types'
import { buildPrivacyReport } from '../../../src/pcap/privacy'
import { DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/profile/presets'
import type { LayerCoverage } from '../../../src/pcap/sanitize/types'

function emptyPlan(level: PcapPlanSnapshot['pcapLevel'] = 'diagnostic'): PcapPlanSnapshot {
  return {
    generationId: 'g-e5',
    pcapLevel: level,
    profileId: `pcap-${level}`,
    profileHash: 'hash',
    format: CaptureFormat.ClassicPcap,
    fileName: 'e5.pcap',
    engineVersion: 'test',
    packets: [],
    droppedPacketNumbers: [],
    timestamps: level === 'diagnostic' ? 'relative' : 'enumerated',
    timestampAnchorSeed: 'test-anchor-seed',
    changeCategoryTotals: {
      mapped: 12,
      redacted: 2,
      'masked-content': 5,
      'preserved-encrypted': 1,
      'preserved-for-diagnostics': 3,
      'user-requested-drop': 0,
      blocked: 0,
    },
    maskedByteCount: 400,
    dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
    dropsByProtocol: {},
  }
}

function okValidation() {
  return {
    validationValid: true,
    validationIssueCount: 0,
    newBlockingIssues: [] as never[],
    preservedBaselineIssues: [] as never[],
  }
}

describe('enterprise step 5 — coverage + leak + gate', () => {
  it('summarizes by disposition: diagnostic media/unsupported are fail-closed gaps', () => {
    const coverage: LayerCoverage[] = [
      { protocol: 'ipv4', offset: 0, length: 4, status: 'covered' },
      { protocol: 'rtp', offset: 40, length: 16, status: 'preserved-unsafe' },
      { protocol: 'http-body', offset: 60, length: 8, status: 'unsupported' },
    ]
    const summary = summarizeSanitizationCoverage({
      plan: emptyPlan(),
      coverage,
      dsbDropped: 1,
      nrbDropped: 2,
      droppedMetadataBlocks: 3,
    })
    expect(summary.mappedSpanCount).toBe(12)
    expect(summary.maskedSpanCount).toBe(5)
    expect(summary.redactedSpanCount).toBe(2)
    // rtp strip-payload + http-body mask-in-place under diagnostic → gaps, not exposed
    expect(summary.failClosedRegions).toBe(2)
    expect(summary.exposedRegions).toBe(0)
    expect(summary.unhandledUnverifiedRegions).toBe(0)
    expect(summary.secretPassthroughBytes).toBe(0)
    expect(summary.coverageComplete).toBe(true)
    expect(summary.dsbDropped).toBe(1)
    expect(summary.nrbDropped).toBe(2)
    expect(summary.prohibitedMetadataBlocks).toBe(0)
  })

  it('leak scanner reports category/hits/packets without original values', () => {
    const artifact = 'safe alias text only'
    const clean = scanArtifactForOriginalLeaks({
      artifact,
      originals: [
        { category: 'phone', value: '+420777123456', packetNumber: 81 },
        { category: 'ipv4', value: '10.1.2.3', packetNumber: 92 },
      ],
    })
    expect(clean.leakHits).toBe(0)
    expect(clean.findings).toEqual([])
    expect(emptyLeakScanResult().leakHits).toBe(0)

    const dirty = scanArtifactForOriginalLeaks({
      artifact: 'contact +420777123456 and host 10.1.2.3',
      originals: [
        { category: 'sip-phone', value: '+420777123456', packetNumber: 81 },
        { category: 'ipv4', value: '10.1.2.3', packetNumber: 92 },
        { category: 'ipv4', value: '10.1.2.3', packetNumber: 93 },
      ],
    })
    expect(dirty.leakHits).toBe(3)
    expect(dirty.findings).toEqual([
      { category: 'IPV4', hits: 2, packetNumbers: [92, 93] },
      { category: 'PHONE', hits: 1, packetNumbers: [81] },
    ])
    const json = JSON.stringify(dirty)
    expect(json).not.toContain('+420')
    expect(json).not.toContain('10.1.2.3')
    expect(json).not.toContain('originalValue')
    expect(mapEntityCategoryToLeak('hostname')).toBe('HOSTNAME')
  })

  it('reports leak hits as gaps (exportable WITH_GAPS after T67)', () => {
    const plan = emptyPlan('diagnostic')
    const privacy = buildPrivacyReport({
      plan,
      policy: DIAGNOSTIC_POLICY,
      unsafeExportAcknowledged: false,
    })
    const report = buildExportReport({
      plan,
      exportedFileName: 'x.pcap',
      changedPackets: 1,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [],
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: okValidation(),
      privacy,
      diagnosticPreset: true,
      coverage: [
        { protocol: 'http-body', offset: 0, length: 4, status: 'preserved-unsafe' },
      ],
      leakOriginals: [
        { category: 'phone', value: '+420777000111', packetNumber: 7 },
      ],
      anonymizedBytes: new TextEncoder().encode('leaked +420777000111 in payload'),
    })

    expect(report.schemaVersion).toBe(8)
    expect(report.sanitization.secretPassthroughBytes).toBe(4)
    expect(report.sanitization.coverageComplete).toBe(false)
    expect(report.leakFindings[0]?.category).toBe('PHONE')
    expect(report.leakFindings[0]?.packetNumbers.length).toBeGreaterThan(0)
    expect(report.gate).toBe('AI_READY_WITH_GAPS')
    expect(report.exportAllowed).toBe(true)
    expect(report.safeForAi).toBe(false)
    expect(report.diagnosticResidualRisk.graph).toBe(true)
    expect(report.diagnosticResidualRisk.timing).toBe(true)

    const json = JSON.stringify(report)
    assertReportHasNoOriginalIdentifiers(json)
    expect(json).not.toContain('+420777000111')
    expect(json).not.toContain('originalValue')
  })

  it('diagnostic clean coverage → AI_READY with residual risk axes', () => {
    const plan = emptyPlan('diagnostic')
    const privacy = buildPrivacyReport({
      plan,
      policy: DIAGNOSTIC_POLICY,
      unsafeExportAcknowledged: false,
    })
    const report = buildExportReport({
      plan,
      exportedFileName: 'x.pcap',
      changedPackets: 0,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [],
      checksum: { fields: [], counts: { ...emptyChecksumCounts(), recomputed: 1 } },
      validation: okValidation(),
      privacy,
      diagnosticPreset: true,
      coverage: [{ protocol: 'ipv4', offset: 0, length: 4, status: 'covered' }],
    })
    expect(report.gate).toBe('AI_READY')
    expect(report.exportAllowed).toBe(true)
    expect(report.diagnosticResidualRisk).toEqual({
      graph: true,
      timing: true,
      topology: true,
      fingerprint: true,
    })

    const ai = buildAiDiagnosticsManifest({
      plan,
      gate: report.gate,
      exportAllowed: report.exportAllowed,
      safeForAi: report.safeForAi,
      diagnosticResidualRisk: report.diagnosticResidualRisk,
      leakFindings: report.leakFindings,
      privacy: report.privacy,
    })
    expect(ai.schemaVersion).toBe(5)
    expect(ai.diagnosticResidualRisk.topology).toBe(true)
    assertReportHasNoOriginalIdentifiers(JSON.stringify(ai))
  })

  it('high-privacy clean is AI_READY; preserve-unsafe residual is WITH_GAPS (T67)', () => {
    const plan = emptyPlan('high-privacy')
    const privacy = buildPrivacyReport({
      plan,
      policy: HIGH_PRIVACY_POLICY,
      unsafeExportAcknowledged: false,
    })
    const ok = buildExportReport({
      plan,
      exportedFileName: 'x.pcap',
      changedPackets: 0,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [],
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: okValidation(),
      privacy,
    })
    expect(ok.gate).toBe('AI_READY')
    expect(ok.exportAllowed).toBe(true)
    expect(ok.safeForAi).toBe(true)

    const checks = buildGateChecksFromCoverage({
      coverage: summarizeSanitizationCoverage({
        plan,
        coverage: [{ protocol: 'http-body', offset: 0, length: 8, status: 'preserved-unsafe' }],
      }),
      leakHits: 0,
      verificationFatalErrors: 0,
      profile: 'high-privacy',
    })
    expect(resolveExportGate({ profile: 'high-privacy', checks }).gate).toBe('AI_READY_WITH_GAPS')
    expect(resolveExportGate({ profile: 'high-privacy', checks }).exportAllowed).toBe(true)
  })

  it('buildDiagnosticResidualRisk mirrors privacy flags', () => {
    const risk = buildDiagnosticResidualRisk({
      profile: 'high-privacy',
      privacy: {
        residualRisks: ['communication-graph', 'packet-lengths'],
        preservesExactTimestampDeltas: false,
        networkFingerprintNormalized: true,
      },
    })
    expect(risk).toEqual({
      graph: true,
      timing: true,
      topology: false,
      fingerprint: false,
    })
  })
})
