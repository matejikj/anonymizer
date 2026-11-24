/**
 * Enterprise step 1 — honest classification vocabulary, validity layers, export gate.
 * profile ≠ gate ≠ validity.
 */

import { describe, expect, it } from 'vitest'
import {
  FIELD_CLASSIFICATIONS,
  GATE_RESULTS,
  buildValidityLayers,
  resolveExportGate,
  gateBadgeFromShareableWithAi,
  isFieldClassification,
  isGateResult,
} from '../../../src/pcap/trust'
import { PCAP_ANONYMIZATION_LEVELS } from '../../../src/pcap/profile/pcapAnonymizationLevel'
import { buildExportReport } from '../../../src/pcap/export/report'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import type { PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import { emptyChecksumCounts } from '../../../src/pcap/checksums/types'
import { buildPrivacyReport } from '../../../src/pcap/privacy'
import { DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/profile/presets'
import { cs } from '../../../src/i18n/cs'
import type { LayerCoverage } from '../../../src/pcap/sanitize/types'

function emptyPlan(level: PcapPlanSnapshot['pcapLevel'] = 'diagnostic'): PcapPlanSnapshot {
  return {
    generationId: 'g-e1',
    pcapLevel: level,
    profileId: `pcap-${level}`,
    profileHash: 'hash',
    format: CaptureFormat.ClassicPcap,
    fileName: 'e1.pcap',
    engineVersion: 'test',
    packets: [],
    droppedPacketNumbers: [],
    timestamps: level === 'diagnostic' ? 'relative' : 'enumerated',
    timestampAnchorSeed: 'test-anchor-seed',
    changeCategoryTotals: {
      mapped: 0,
      redacted: 0,
      'masked-content': 0,
      'preserved-encrypted': 0,
      'preserved-for-diagnostics': 0,
      'user-requested-drop': 0,
      blocked: 0,
    },
    maskedByteCount: 0,
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

describe('enterprise step 1 — vocabulary', () => {
  it('exposes eight field classifications including UNKNOWN_UNVERIFIED', () => {
    expect(FIELD_CLASSIFICATIONS).toEqual([
      'IDENTITY',
      'SECRET',
      'MEDIA',
      'UNKNOWN_UNVERIFIED',
      'FINGERPRINT',
      'TIMING',
      'ENCRYPTED_OPAQUE',
      'SAFE_METADATA',
    ])
    expect(isFieldClassification('UNKNOWN_UNVERIFIED')).toBe(true)
    expect(isFieldClassification('UNKNOWN_PLAINTEXT')).toBe(false)
  })

  it('keeps profile and gate as separate enums (no HIGH_PRIVACY gate value)', () => {
    expect(GATE_RESULTS).toEqual(['AI_READY', 'AI_READY_WITH_GAPS', 'NOT_AI_READY'])
    expect(PCAP_ANONYMIZATION_LEVELS).toEqual(['diagnostic', 'high-privacy'])
    expect(isGateResult('AI_READY')).toBe(true)
    expect(isGateResult('SAFE_FOR_AI')).toBe(true) // legacy alias
    expect(isGateResult('HIGH_PRIVACY')).toBe(false)
    expect(isGateResult('DIAGNOSTIC_SAFE')).toBe(false)
  })

  it('resolves three-state gate; high-privacy may carry AI_READY', () => {
    expect(
      resolveExportGate({ profile: 'diagnostic', sanitizationIncomplete: false }),
    ).toEqual({
      profile: 'diagnostic',
      gate: 'AI_READY',
      exportAllowed: true,
      safeForAi: true,
      aiReadyWithGaps: false,
    })
    expect(
      resolveExportGate({ profile: 'diagnostic', sanitizationIncomplete: true }),
    ).toEqual({
      profile: 'diagnostic',
      gate: 'NOT_AI_READY',
      exportAllowed: false,
      safeForAi: false,
      aiReadyWithGaps: false,
    })
    expect(
      resolveExportGate({ profile: 'high-privacy', sanitizationIncomplete: false }),
    ).toEqual({
      profile: 'high-privacy',
      gate: 'AI_READY',
      exportAllowed: true,
      safeForAi: true,
      aiReadyWithGaps: false,
    })
    expect(
      resolveExportGate({ profile: 'high-privacy', sanitizationIncomplete: true }),
    ).toEqual({
      profile: 'high-privacy',
      gate: 'NOT_AI_READY',
      exportAllowed: false,
      safeForAi: false,
      aiReadyWithGaps: false,
    })
    expect(gateBadgeFromShareableWithAi(true)).toBe('AI_READY')
  })

  it('requires full check vector for AI_READY including diagnostic invariants', () => {
    const base = {
      unhandledUnverifiedRegions: 0,
      leakHits: 0,
      secretPassthroughBytes: 0,
      prohibitedMetadataBlocks: 0,
      verificationFatalErrors: 0,
      coverageComplete: true,
      packetCountInvariant: 'PASS' as const,
      packetOrderInvariant: 'PASS' as const,
      packetLengthInvariant: 'PASS' as const,
      timestampDeltaInvariant: 'PASS' as const,
    }
    expect(resolveExportGate({ profile: 'diagnostic', checks: base }).safeForAi).toBe(true)
    expect(
      resolveExportGate({
        profile: 'diagnostic',
        checks: { ...base, packetLengthInvariant: 'FAIL' },
      }).gate,
    ).toBe('NOT_AI_READY')
    expect(
      resolveExportGate({
        profile: 'diagnostic',
        checks: { ...base, leakHits: 1 },
      }).exportAllowed,
    ).toBe(false)
    expect(
      resolveExportGate({
        profile: 'diagnostic',
        checks: { ...base, failClosedRegions: 2, incidentCount: 1 },
      }).gate,
    ).toBe('AI_READY_WITH_GAPS')
  })
})

describe('enterprise step 1 — export report validity + gate', () => {
  it('embeds validity + gate without exportClassification profile conflation', () => {
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
      checksum: {
        fields: [],
        counts: { ...emptyChecksumCounts(), recomputed: 3 },
      },
      validation: okValidation(),
      privacy,
      diagnosticPreset: true,
    })

    expect(report.schemaVersion).toBe(8)
    expect(report.pcapLevel).toBe('diagnostic')
    expect(report.validity).toEqual({
      capture_structure: 'VALID',
      network_checksums: 'VALID',
      application_structure: 'VALID',
      cryptographic_integrity: 'UNKNOWN',
    })
    expect(report.gate).toBe('AI_READY')
    expect(report.exportAllowed).toBe(true)
    expect(report.safeForAi).toBe(true)
    expect(report).not.toHaveProperty('exportClassification')
  })

  it('marks high-privacy clean export AI_READY (gate describes output, not level)', () => {
    const plan = emptyPlan('high-privacy')
    const privacy = buildPrivacyReport({
      plan,
      policy: HIGH_PRIVACY_POLICY,
      unsafeExportAcknowledged: false,
    })
    const report = buildExportReport({
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
    expect(report.pcapLevel).toBe('high-privacy')
    expect(report.gate).toBe('AI_READY')
    expect(report.exportAllowed).toBe(true)
    expect(report.safeForAi).toBe(true)
  })

  it('blocks diagnostic when privacy requires unsafe ack without acknowledgement', () => {
    const plan = emptyPlan('diagnostic')
    const privacy = buildPrivacyReport({
      plan,
      policy: DIAGNOSTIC_POLICY,
      coverage: [
        {
          protocol: 'rtp',
          offset: 0,
          length: 8,
          status: 'preserved-unsafe',
        } satisfies LayerCoverage,
      ],
      unsafeExportAcknowledged: false,
    })
    expect(privacy.requiresUnsafeConfirmation).toBe(true)
    const report = buildExportReport({
      plan,
      exportedFileName: 'x.pcap',
      changedPackets: 0,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [],
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: okValidation(),
      privacy,
      diagnosticPreset: true,
    })
    expect(report.gate).toBe('NOT_AI_READY')
    expect(report.exportAllowed).toBe(false)
    expect(report.safeForAi).toBe(false)
  })

  it('sets application_structure UNKNOWN when unsupported layers exist', () => {
    const layers = buildValidityLayers({
      validationValid: true,
      unsupportedLayers: 2,
      checksumCounts: emptyChecksumCounts(),
    })
    expect(layers.application_structure).toBe('UNKNOWN')
    expect(layers.capture_structure).toBe('VALID')
  })
})

describe('enterprise step 1 — honest product copy', () => {
  it('completion and limits copy avoid unqualified anonymization claims', () => {
    expect(cs.correlationCompletion.honestyNote.toLowerCase()).toContain('pseudonymizace')
    expect(cs.correlationCompletion.honestyNote.toLowerCase()).toContain('sanitizace')
    expect(cs.correlationCompletion.aiReadyBadge).toBe('AI READY')
    expect(cs.correlationCompletion.aiReadyWithGapsBadge).toBe('AI READY WITH GAPS')
    expect(cs.correlationCompletion.notAiReadyBadge).toBe('NOT AI READY')
    expect(cs.help.notItems.some((s) => /sanitizace|pseudonymizace/i.test(s))).toBe(true)
    expect(cs.pcap.presets.diagnosticImpact.toLowerCase()).toContain('pseudonymizaci')
  })
})
