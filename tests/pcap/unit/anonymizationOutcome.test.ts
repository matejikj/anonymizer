/**
 * T10 — anonymization outcome view model + compact packet ranges.
 */
import { describe, expect, it } from 'vitest'
import {
  buildAnonymizationOutcome,
  buildAnonymizationOutcomeForExport,
  compactPacketRanges,
  computeMaskedPacketRanges,
} from '../../../src/pcap/coverage/anonymizationOutcome'
import type { PcapProtocolCoverageRow } from '../../../src/pcap/coverage/pcapCoverageViewModel'
import type { PcapPlanPacket, PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import { EMPTY_INCIDENT_LOG_SNAPSHOT } from '../../../src/domain/anonymizationIncident'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import { emptyPlanChangeCounts } from '../../../src/pcap/plan/planDisposition'

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

describe('buildAnonymizationOutcome', () => {
  it('marks AI_READY when families are anonymized', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [
        row({ protocol: 'sip', familyId: 'sip', familyLabel: 'SIP' }),
        row({ protocol: 'dns', familyId: 'dns-mdns', familyLabel: 'DNS/mDNS' }),
      ],
      gate: 'AI_READY',
      plan: minimalPlan(),
      preset: 'diagnostic',
    })
    expect(outcome.gate).toBe('AI_READY')
    expect(outcome.families.every((f) => f.state === 'anonymized')).toBe(true)
    expect(outcome.summarySentence).toContain('připravený pro AI')
    expect(outcome.maskedPacketRanges).toEqual([])
  })

  it('T11 MGCP covered family is covered state, not masked-without-analysis', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [
        row({
          protocol: 'mgcp',
          familyId: 'mgcp',
          familyLabel: 'MGCP',
          dominantStatus: 'covered',
          dominantUiStatus: 'covered',
          userVerdict: 'protected-export',
        }),
      ],
      gate: 'AI_READY',
      plan: minimalPlan(),
      preset: 'diagnostic',
    })
    expect(outcome.families[0]?.state).toBe('anonymized')
    expect(outcome.diagnosticImpact.analyzableFamilyCount).toBe(1)
  })

  it('worst-of folds needs-attention over anonymized in same family', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [
        row({ protocol: 'tls', familyId: 'tls', familyLabel: 'TLS' }),
        row({
          protocol: 'tls-serverhello',
          familyId: 'tls',
          familyLabel: 'TLS',
          dominantStatus: 'preserved-unsafe',
          dominantUiStatus: 'exposed',
          userVerdict: 'recognized-risk-diagnostic',
          recognizedPacketCount: 12,
        }),
      ],
      gate: 'NOT_AI_READY',
      plan: minimalPlan(),
      preset: 'diagnostic',
    })
    const tls = outcome.families.find((f) => f.familyId === 'tls')
    expect(tls?.state).toBe('needs-attention')
    expect(outcome.summarySentence).toContain('není připravený pro AI')
    expect(tls?.recommendation).toContain('Vysoké soukromí')
  })

  it('marks masked-without-analysis for unsupported/heuristic', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [
        row({
          protocol: 'unsupported:mgcp',
          familyId: 'identified-unsupported',
          familyLabel: 'Identifikované nepodporované',
          dominantStatus: 'unsupported',
          dominantUiStatus: 'unsupported',
          userVerdict: 'protected-export-no-full-analysis',
          probableIdentification: true,
        }),
      ],
      gate: 'AI_READY_WITH_GAPS',
      plan: minimalPlan(),
      preset: 'diagnostic',
    })
    expect(outcome.families[0]?.state).toBe('masked-without-analysis')
    expect(outcome.summarySentence).toContain('s omezením')
  })

  it('folds processing-failed from incidents', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [row({ protocol: 'sip', familyId: 'sip', familyLabel: 'SIP' })],
      gate: 'AI_READY_WITH_GAPS',
      plan: minimalPlan({
        incidents: {
          ...EMPTY_INCIDENT_LOG_SNAPSHOT,
          totalFailures: 1,
          incidents: [
            {
              unit: 'packet',
              sourceId: 't',
              packetNumber: 5,
              protocol: 'sip',
              stage: 'plan',
              reason: 'sanitizer-exception',
              fallback: 'packet-masked',
            },
          ],
          aggregates: [
            { protocol: 'sip', reason: 'sanitizer-exception', fallback: 'packet-masked', count: 1 },
          ],
        },
      }),
      preset: 'diagnostic',
    })
    expect(outcome.families.find((f) => f.familyId === 'sip')?.state).toBe('processing-failed')
    expect(outcome.incidentTotal).toBe(1)
    expect(outcome.incidents[0]?.reasonLabel).toContain('sanitizer')
  })
})

describe('buildAnonymizationOutcomeForExport', () => {
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
