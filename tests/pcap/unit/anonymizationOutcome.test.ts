/**
 * T10 / T67 — anonymization outcome view model (ledger-lite, no review CTAs).
 */
import { describe, expect, it } from 'vitest'
import {
  buildAnonymizationOutcome,
  buildAnonymizationOutcomeForExport,
  compactPacketRanges,
  computeMaskedPacketRanges,
  coverageRowsFromProtocolSummaries,
  OUTCOME_FAMILY_STATES,
} from '../../../src/pcap/coverage/anonymizationOutcome'
import type { UnifiedProtocolSummary } from '../../../src/pcap/coverage/types'
import type { PcapProtocolCoverageRow } from '../../../src/pcap/coverage/pcapCoverageViewModel'
import type { PcapPlanPacket, PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import { EMPTY_INCIDENT_LOG_SNAPSHOT } from '../../../src/domain/anonymizationIncident'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import { emptyPlanChangeCounts } from '../../../src/pcap/plan/planDisposition'
import { protocolPrivacyGuidance } from '../../../src/pcap/coverage/protocolPrivacyGuidance'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { buildAiDiagnosticsManifest } from '../../../src/pcap/export/aiDiagnostics'

function row(
  partial: Partial<PcapProtocolCoverageRow> & Pick<PcapProtocolCoverageRow, 'protocol' | 'familyId'>,
): PcapProtocolCoverageRow {
  return {
    familyLabel: partial.familyId,
    probableIdentification: false,
    recognizedPacketCount: 10,
    protectedPacketCount: 10,
    layerKind: 'both',
    dominantStatus: 'covered',
    dominantUiStatus: 'covered',
    userVerdict: 'recognized-and-protected',
    userVerdictLabel: 'ok',
    technicalSourceLabel: '',
    unsupportedCount: 0,
    filterProtocol: partial.protocol,
    ...partial,
  }
}

function pkt(
  packetNumber: number,
  opts: { masked?: boolean } = {},
): PcapPlanPacket {
  const masked = opts.masked === true
  return {
    index: packetNumber - 1,
    packetNumber,
    drop: false,
    patches: [],
    originalCapturedLength: 64,
    originalLength: 64,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    originalTimestamp: { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    dispositionReason: 'exported',
    changeCounts: {
      ...emptyPlanChangeCounts(),
      ...(masked ? { 'masked-content': 1 } : { mapped: 1 }),
    },
    maskedByteCount: masked ? 16 : 0,
  }
}

function minimalPlan(overrides: Partial<PcapPlanSnapshot> = {}): PcapPlanSnapshot {
  return {
    generationId: 'g1',
    profileId: 'pcap-diagnostic',
    profileHash: 'h',
    policyHash: 'h',
    pcapLevel: 'diagnostic',
    engineVersion: 'test',
    format: CaptureFormat.ClassicPcap,
    fileName: 't.pcap',
    packets: [pkt(1), pkt(2, { masked: true }), pkt(3, { masked: true })],
    droppedPacketNumbers: [],
    timestamps: 'relative',
    timestampAnchorSeed: 'seed',
    changeCategoryTotals: {
      ...emptyPlanChangeCounts(),
      mapped: 1,
      'masked-content': 2,
    },
    maskedByteCount: 32,
    dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
    dropsByProtocol: {},
    incidents: EMPTY_INCIDENT_LOG_SNAPSHOT,
    ...overrides,
  }
}

const FORBIDDEN_REVIEW = /ověř(?!iteln)|zkontrol|odstraňte|posuzujte|k prověření|needs-attention|needsReview/i

describe('compactPacketRanges', () => {
  it('compacts consecutive numbers', () => {
    expect(compactPacketRanges([317, 318, 319, 320, 322, 325, 326])).toEqual([
      '317-320',
      '322',
      '325-326',
    ])
  })

  it('dedupes and sorts', () => {
    expect(compactPacketRanges([3, 1, 2, 2])).toEqual(['1-3'])
  })
})

describe('buildAnonymizationOutcome (T67)', () => {
  it('has guidance for every application handler', () => {
    for (const handler of APPLICATION_HANDLER_ORDER) {
      expect(protocolPrivacyGuidance(handler.id).known, handler.id).toBe(true)
    }
    expect(protocolPrivacyGuidance('unsupported:mgcp').known).toBe(false)
  })

  it('family states are only anonymized / with-loss / encrypted-kept', () => {
    expect([...OUTCOME_FAMILY_STATES].sort()).toEqual(
      ['anonymized', 'anonymized-with-loss', 'encrypted-kept'].sort(),
    )
  })

  it('lists detected protocols and uses level-property check copy (no review CTA)', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [
        row({ protocol: 'udp', familyId: 'network-headers' }),
        row({ protocol: 'ipv4', familyId: 'network-headers' }),
        row({ protocol: 'h248', familyId: 'sip' }),
      ],
      gate: 'AI_READY',
      plan: minimalPlan(),
      preset: 'diagnostic',
    })
    const network = outcome.families.find((f) => f.familyId === 'network-headers')!
    expect(network.protocols.map((p) => p.id).sort()).toEqual(['ipv4', 'udp'])
    expect(network.protocols.find((p) => p.id === 'udp')?.check).toBeTruthy()
    expect(FORBIDDEN_REVIEW.test(network.protocols.find((p) => p.id === 'udp')!.check)).toBe(false)
    expect(outcome.families.find((f) => f.familyId === 'sip')?.protocols.map((p) => p.id)).toEqual([
      'h248',
    ])
  })

  it('preserved-unsafe / heuristic become anonymized-with-loss and escalate gate to WITH_GAPS', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [
        row({
          protocol: 'dmr-voice',
          familyId: 'dmr',
          dominantStatus: 'preserved-unsafe',
          dominantUiStatus: 'exposed',
          userVerdict: 'recognized-risk-diagnostic',
        }),
      ],
      gate: 'AI_READY',
      plan: minimalPlan(),
      preset: 'diagnostic',
    })
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.families[0]?.state).toBe('anonymized-with-loss')
    expect(outcome.diagnosticImpact.needsAttentionFamilyCount).toBe(0)
    expect(JSON.stringify(outcome)).not.toMatch(/needsReview|needs-attention/)
    expect(FORBIDDEN_REVIEW.test(outcome.summarySentence)).toBe(false)
    expect(FORBIDDEN_REVIEW.test(outcome.assuranceNote)).toBe(false)
  })

  it('redacted unknown content is anonymized-with-loss, not a review state', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [row({ protocol: 'payload', familyId: 'other', dominantStatus: 'redacted' })],
      gate: 'AI_READY',
      plan: minimalPlan(),
      preset: 'diagnostic',
    })
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.families[0]?.state).toBe('anonymized-with-loss')
    expect(JSON.stringify(outcome)).not.toMatch(/100\s*%|stoprocent|důvěryhodně anonymní/i)
  })

  it('encrypted content stays encrypted-kept', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [
        row({
          protocol: 'tls-encrypted-payload',
          familyId: 'tls',
          dominantStatus: 'encrypted',
          userVerdict: 'encrypted-preserved',
        }),
      ],
      gate: 'AI_READY',
      plan: minimalPlan(),
      preset: 'diagnostic',
    })
    expect(outcome.families[0]?.state).toBe('encrypted-kept')
    expect(outcome.gate).toBe('AI_READY')
  })

  it('covered without loss stays anonymized; AI_READY summary uses level wording', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [
        row({ protocol: 'sip', familyId: 'sip' }),
        row({ protocol: 'dns', familyId: 'dns' }),
      ],
      gate: 'AI_READY',
      plan: minimalPlan(),
      preset: 'diagnostic',
    })
    expect(outcome.gate).toBe('AI_READY')
    expect(outcome.families.every((f) => f.state === 'anonymized')).toBe(true)
    expect(outcome.summarySentence).toContain('Anonymizováno pro diagnostickou úroveň')
    expect(outcome.summarySentence).toMatch(/předat AI/)
  })

  it('incidents fold into anonymized-with-loss without processing-failed family state', () => {
    const incident = {
      unit: 'packet' as const,
      sourceId: 't',
      packetNumber: 1,
      protocol: 'http',
      stage: 'plan' as const,
      reason: 'sanitizer-exception' as const,
      fallback: 'packet-masked' as const,
    }
    const outcome = buildAnonymizationOutcome({
      protocols: [row({ protocol: 'http', familyId: 'http' })],
      gate: 'AI_READY',
      preset: 'diagnostic',
      plan: minimalPlan({
        incidents: {
          ...EMPTY_INCIDENT_LOG_SNAPSHOT,
          totalFailures: 1,
          incidents: [incident],
        },
      }),
    })
    expect(outcome.families[0]?.state).toBe('anonymized-with-loss')
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
  })
})

describe('masked and redacted content is not reported as left readable', () => {
  const summary = (
    protocol: string,
    dominantStatus: UnifiedProtocolSummary['dominantStatus'],
    structural: boolean,
  ) => ({
    protocol,
    packetCount: 5,
    spanCount: 5,
    unsupportedCount: dominantStatus === 'unsupported' ? 5 : 0,
    structuralSpanCount: structural ? 5 : 0,
    sanitizerSpanCount: structural ? 0 : 5,
    dominantStatus,
    issues: [],
  })

  const summaries: UnifiedProtocolSummary[] = [
    summary('arp', 'covered', true),
    summary('arp-padding', 'redacted', false),
    summary('ethernet', 'unsupported', true),
    summary('ether-0x8ffd', 'unsupported', false),
    summary('icmp-echo-payload', 'redacted', false),
    summary('radio-protocol-body', 'covered', false),
    summary('lldp', 'redacted', false),
    summary('syslog', 'redacted', false),
  ]

  it.each(['diagnostic', 'high-privacy'] as const)(
    '%s: no review fields; gaps stay informational',
    (preset) => {
      const outcome = buildAnonymizationOutcome({
        protocols: coverageRowsFromProtocolSummaries(summaries, preset),
        gate: 'AI_READY',
        plan: minimalPlan(),
        preset,
      })
      expect(outcome.diagnosticImpact.needsAttentionFamilyCount).toBe(0)
      expect(JSON.stringify(outcome)).not.toMatch(/needsReview|"needs-attention"/)
      expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    },
  )

  it('heuristic text is anonymized-with-loss (T64 mask), never a review flag', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: coverageRowsFromProtocolSummaries(
        [summary('http-body', 'heuristic', false)],
        'diagnostic',
      ),
      gate: 'AI_READY',
      plan: minimalPlan(),
      preset: 'diagnostic',
    })
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.families[0]?.state).toBe('anonymized-with-loss')
    expect(FORBIDDEN_REVIEW.test(outcome.families[0]!.protocols[0]!.check)).toBe(false)
  })
})

describe('buildAnonymizationOutcomeForExport', () => {
  it.each(['AI_READY', 'AI_READY_WITH_GAPS', 'NOT_AI_READY'] as const)(
    'preserves the final verified export gate %s in diagnostics and nested outcome',
    (gate) => {
      const manifest = buildAiDiagnosticsManifest({
        plan: minimalPlan(),
        gate,
        protocolCoverage: [
          {
            protocol: 'http-body',
            packetCount: 1,
            spanCount: 1,
            unsupportedCount: 0,
            structuralSpanCount: 0,
            sanitizerSpanCount: 1,
            dominantStatus: 'heuristic',
            issues: [],
          },
        ],
      })
      expect(manifest.gate).toBe(gate)
      expect(manifest.anonymizationOutcome.verdict).toBe(gate)
      expect(manifest.safeForAi).toBe(gate === 'AI_READY')
    },
  )

  it('includes compact masked packet ranges and schema fields', () => {
    const section = buildAnonymizationOutcomeForExport({
      protocolCoverage: [
        {
          protocol: 'sip',
          packetCount: 2,
          spanCount: 2,
          unsupportedCount: 0,
          structuralSpanCount: 1,
          sanitizerSpanCount: 1,
          dominantStatus: 'covered',
          issues: [],
        },
      ],
      gate: 'AI_READY',
      plan: minimalPlan(),
      preset: 'diagnostic',
    })
    expect(section.verdict).toBe('AI_READY')
    expect(section.maskedPacketRanges).toEqual(['2-3'])
    expect(computeMaskedPacketRanges(minimalPlan())).toEqual(['2-3'])
    expect(section.families.some((f) => f.familyId === 'sip')).toBe(true)
  })
})
