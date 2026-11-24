/**
 * Stage 6 — PcapCoverageViewModel dominant-status matrix and user verdicts.
 */
import { describe, expect, it } from 'vitest'
import {
  buildPcapCoverageViewModel,
  buildPlanRevision,
  coverageStatusToUiStatus,
  dominantUiStatus,
  layerKindFromCounts,
  spanExportAction,
  userVerdictForProtocol,
} from '../../src/pcap/coverage/pcapCoverageViewModel'
import { dominantStatus } from '../../src/pcap/coverage/mergeRules'
import type { UnifiedCoverageModel } from '../../src/pcap/coverage/types'
import type { SanitizationPolicy } from '../../src/pcap/sanitize/types'
import type { PcapPlanSnapshot } from '../../src/pcap/export/planSnapshot'
import type { CoverageStatus } from '../../src/pcap/sanitize/types'
import { DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../src/pcap/sanitize'

const STATUSES: CoverageStatus[] = [
  'covered',
  'truncated',
  'unsupported',
  'malformed',
  'heuristic',
  'preserved-unsafe',
  'requires-reassembly',
  'encrypted',
]

function emptyPlan(): PcapPlanSnapshot {
  return {
    generationId: 'g1',
    profileId: 'p',
    profileHash: 'hash',
    format: 0,
    fileName: 't.pcap',
    engineVersion: '1',
    packets: [],
    droppedPacketNumbers: [],
        timestamps: 'relative',
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

function policy(partial: Partial<SanitizationPolicy> & Pick<SanitizationPolicy, 'preset'>): SanitizationPolicy {
  const base =
    partial.preset === 'high-privacy'
      ? HIGH_PRIVACY_POLICY
      : DIAGNOSTIC_POLICY
  return { ...base, ...partial }
}

function modelFromProtocol(input: {
  protocol: string
  packetCount: number
  structural: number
  sanitizer: number
  status: CoverageStatus
  unsupported?: number
}): UnifiedCoverageModel {
  return {
    perPacket: [
      [
        {
          packetIndex: 0,
          protocol: input.protocol,
          source: input.sanitizer > 0 && input.structural === 0 ? 'sanitizer' : 'structural',
          offset: 0,
          length: 8,
          status: input.status,
          issues: [],
        },
      ],
    ],
    byProtocol: [
      {
        protocol: input.protocol,
        packetCount: input.packetCount,
        spanCount: input.structural + input.sanitizer,
        unsupportedCount: input.unsupported ?? 0,
        structuralSpanCount: input.structural,
        sanitizerSpanCount: input.sanitizer,
        dominantStatus: input.status,
        issues: [],
      },
    ],
    histogram: new Map([[input.protocol, input.packetCount]]),
    totalUnsupportedSpans: input.unsupported ?? 0,
    totalTruncatedSpans: input.status === 'truncated' ? 1 : 0,
    totalHeuristicSpans: input.status === 'heuristic' ? 1 : 0,
  }
}

describe('Stage 6 PcapCoverageViewModel', () => {
  it('dominant UI matrix covers all CoverageStatus values', () => {
    for (const a of STATUSES) {
      for (const b of STATUSES) {
        const ui = dominantUiStatus(coverageStatusToUiStatus(a), coverageStatusToUiStatus(b))
        expect(STATUSES.map(coverageStatusToUiStatus)).toContain(ui)
        // Domain dominant stays authoritative for span merge.
        expect(dominantStatus(a, b)).toBeTruthy()
      }
    }
  })

  it('maps span export actions for every coverage status', () => {
    expect(spanExportAction('covered')).toBe('mapped')
    expect(spanExportAction('truncated')).toBe('truncated')
    expect(spanExportAction('heuristic')).toBe('heuristic')
    expect(spanExportAction('requires-reassembly')).toBe('unverifiable')
    expect(spanExportAction('malformed')).toBe('blocked')
    expect(spanExportAction('unsupported')).toBe('preserved')
    expect(spanExportAction('encrypted')).toBe('preserved')
    expect(spanExportAction('unsupported', { blocking: true })).toBe('blocked')
  })

  it('sanitizer-only protocol gets protected-export-no-full-analysis verdict', () => {
    expect(layerKindFromCounts(0, 3)).toBe('sanitizer')
    expect(
      userVerdictForProtocol({
        layerKind: 'sanitizer',
        dominantStatus: 'covered',
        truncateUnsupported: true,
        preset: 'diagnostic',
      }),
    ).toBe('protected-export-no-full-analysis')

    const vm = buildPcapCoverageViewModel({
      unifiedCoverage: modelFromProtocol({
        protocol: 'dns',
        packetCount: 4,
        structural: 0,
        sanitizer: 4,
        status: 'covered',
      }),
      policy: policy({ preset: 'high-privacy' }),
      plan: emptyPlan(),
      statuses: {
        anonymization: 'covered',
        integrity: 'ok',
        compatibility: 'valid',
        truncatedCount: 0,
        unsupportedCount: 0,
        droppedCount: 0,
        changedCount: 2,
        reassemblyCount: 0,
        issueCount: 0,
      },
      generationId: 'g1',
      mappingRevision: 1,
      profileHash: 'h',
    })
    expect(vm.protocols[0]!.userVerdict).toBe('protected-export-no-full-analysis')
    expect(vm.protocols[0]!.recognizedPacketCount).toBe(4)
    expect(vm.summary.exportLooksSafe).toBe(true)
    expect(vm.summary.primaryAction).toBe('export-safe')
  })

  it('diagnostic mapped fingerprints do not require unsafe confirmation (step 7/9)', () => {
    const vm = buildPcapCoverageViewModel({
      unifiedCoverage: modelFromProtocol({
        protocol: 'dns',
        packetCount: 1,
        structural: 0,
        sanitizer: 1,
        status: 'covered',
      }),
      policy: policy({ preset: 'diagnostic' }),
      plan: emptyPlan(),
      statuses: {
        anonymization: 'covered',
        integrity: 'ok',
        compatibility: 'valid',
        truncatedCount: 0,
        unsupportedCount: 0,
        droppedCount: 0,
        changedCount: 0,
        reassemblyCount: 0,
        issueCount: 0,
      },
      generationId: 'g1',
      mappingRevision: 1,
      profileHash: 'h',
    })
    expect(vm.summary.exportLooksSafe).toBe(true)
    expect(vm.summary.primaryAction).toBe('export-safe')
  })

  it('structural-only unsupported on high-privacy truncates; diagnostic masks in place', () => {
    expect(
      userVerdictForProtocol({
        layerKind: 'structural',
        dominantStatus: 'unsupported',
        truncateUnsupported: true,
        preset: 'high-privacy',
      }),
    ).toBe('recognized-truncated-safe')
    // The diagnostic level's unsupportedPayloadPolicy is mask-in-place: the export masks it.
    expect(
      userVerdictForProtocol({
        layerKind: 'structural',
        dominantStatus: 'unsupported',
        truncateUnsupported: false,
        preset: 'diagnostic',
      }),
    ).toBe('protected-export-no-full-analysis')
    // Only an explicit preserve-unsafe policy leaves the payload as a risk.
    expect(
      userVerdictForProtocol({
        layerKind: 'structural',
        dominantStatus: 'unsupported',
        truncateUnsupported: false,
        preset: 'diagnostic',
        unsupportedPayloadPolicy: 'preserve-unsafe',
      }),
    ).toBe('recognized-risk-diagnostic')
  })

  it('heuristic stays a review verdict regardless of level', () => {
    for (const preset of ['diagnostic', 'high-privacy'] as const) {
      expect(userVerdictForProtocol({
        layerKind: 'sanitizer', dominantStatus: 'heuristic', truncateUnsupported: preset === 'high-privacy', preset,
      })).toBe('heuristic')
    }
  })

  it('redacted content is protected, never reported as preserved', () => {
    for (const layerKind of ['sanitizer', 'structural', 'both'] as const) {
      for (const preset of ['diagnostic', 'high-privacy'] as const) {
        expect(
          userVerdictForProtocol({
            layerKind,
            dominantStatus: 'redacted',
            truncateUnsupported: preset === 'high-privacy',
            preset,
          }),
        ).toBe('protected-export-no-full-analysis')
      }
    }
  })

  it('both layer kind and recognized-and-protected for covered both', () => {
    expect(layerKindFromCounts(2, 2)).toBe('both')
    expect(
      userVerdictForProtocol({
        layerKind: 'both',
        dominantStatus: 'covered',
        truncateUnsupported: true,
        preset: 'high-privacy',
      }),
    ).toBe('recognized-and-protected')
  })

  it('plan revision changes when mapping or profile hash changes', () => {
    const a = buildPlanRevision({
      generationId: 'g',
      mappingRevision: 1,
      profileHash: 'a',
      planPacketCount: 10,
    })
    const b = buildPlanRevision({
      generationId: 'g',
      mappingRevision: 2,
      profileHash: 'a',
      planPacketCount: 10,
    })
    const c = buildPlanRevision({
      generationId: 'g',
      mappingRevision: 1,
      profileHash: 'b',
      planPacketCount: 10,
    })
    expect(a).not.toBe(b)
    expect(a).not.toBe(c)
  })

  it('summary never looks safe when anonymization is exposed or blocked', () => {
    const exposed = buildPcapCoverageViewModel({
      unifiedCoverage: modelFromProtocol({
        protocol: 'udp',
        packetCount: 1,
        structural: 1,
        sanitizer: 0,
        status: 'unsupported',
      }),
      policy: {
        ...DIAGNOSTIC_POLICY,
        unsupportedPayloadPolicy: 'preserve-unsafe',
        truncateUnsupported: false,
      },
      plan: emptyPlan(),
      statuses: {
        anonymization: 'exposed',
        integrity: 'warnings',
        compatibility: 'valid',
        truncatedCount: 0,
        unsupportedCount: 1,
        droppedCount: 0,
        changedCount: 0,
        reassemblyCount: 0,
        issueCount: 1,
      },
      generationId: 'g',
      mappingRevision: 3,
      profileHash: 'x',
    })
    expect(exposed.summary.exportLooksSafe).toBe(false)
    expect(exposed.summary.primaryAction).toBe('confirm-exposed')
    expect(exposed.summary.reasons.length).toBeGreaterThan(0)
    expect(exposed.summary.reasons.length).toBeLessThanOrEqual(3)

    const unsafeMedia = buildPcapCoverageViewModel({
      unifiedCoverage: modelFromProtocol({
        protocol: 'sip',
        packetCount: 1,
        structural: 1,
        sanitizer: 1,
        status: 'covered',
      }),
      policy: policy({ preset: 'diagnostic', mediaPolicy: 'preserve-unsafe' }),
      plan: emptyPlan(),
      statuses: {
        anonymization: 'covered',
        integrity: 'ok',
        compatibility: 'valid',
        truncatedCount: 0,
        unsupportedCount: 0,
        droppedCount: 0,
        changedCount: 1,
        reassemblyCount: 0,
        issueCount: 0,
      },
      generationId: 'g',
      mappingRevision: 4,
      profileHash: 'media',
    })
    expect(unsafeMedia.summary.exportLooksSafe).toBe(false)
    expect(unsafeMedia.summary.primaryAction).toBe('confirm-exposed')
    expect(unsafeMedia.summary.reasons.some((r) => r.includes('není bezpečný'))).toBe(true)

    const blocked = buildPcapCoverageViewModel({
      unifiedCoverage: modelFromProtocol({
        protocol: 'eth',
        packetCount: 1,
        structural: 1,
        sanitizer: 0,
        status: 'malformed',
      }),
      policy: policy({ preset: 'high-privacy' }),
      plan: emptyPlan(),
      statuses: {
        anonymization: 'blocked',
        integrity: 'unverifiable',
        compatibility: 'blocked',
        truncatedCount: 0,
        unsupportedCount: 0,
        droppedCount: 0,
        changedCount: 0,
        reassemblyCount: 0,
        issueCount: 2,
      },
      generationId: 'g',
      mappingRevision: 4,
      profileHash: 'y',
    })
    expect(blocked.summary.canExport).toBe(false)
    expect(blocked.summary.primaryAction).toBe('blocked')
  })

  it('spansForPacket exposes i18n export action labels', () => {
    const vm = buildPcapCoverageViewModel({
      unifiedCoverage: modelFromProtocol({
        protocol: 'sip',
        packetCount: 1,
        structural: 0,
        sanitizer: 1,
        status: 'covered',
      }),
      policy: policy({ preset: 'diagnostic' }),
      plan: emptyPlan(),
      statuses: {
        anonymization: 'covered',
        integrity: 'ok',
        compatibility: 'valid',
        truncatedCount: 0,
        unsupportedCount: 0,
        droppedCount: 0,
        changedCount: 1,
        reassemblyCount: 0,
        issueCount: 0,
      },
      generationId: 'g',
      mappingRevision: 1,
      profileHash: 'h',
    })
    const spans = vm.spansForPacket(0)
    expect(spans[0]!.exportAction).toBe('mapped')
    expect(spans[0]!.exportActionLabel).toBe('mapováno')
  })
})
