/**
 * T10 — anonymization outcome view model + compact packet ranges.
 */
import { describe, expect, it } from 'vitest'
import {
  buildAnonymizationOutcome,
  buildAnonymizationOutcomeForExport,
  compactPacketRanges,
  computeMaskedPacketRanges,
  coverageRowsFromProtocolSummaries,
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
  it('has specific guidance for every application handler without advertising unsupported variants as supported', () => {
    for (const handler of APPLICATION_HANDLER_ORDER) {
      expect(protocolPrivacyGuidance(handler.id).known, handler.id).toBe(true)
    }
    expect(protocolPrivacyGuidance('unsupported:mgcp').known).toBe(false)
    expect(protocolPrivacyGuidance('http-unregistered-extension').id).toBe('http')
    expect(protocolPrivacyGuidance('http2-headers').id).toBe('http2')
    expect(protocolPrivacyGuidance('httpx-new').known).toBe(false)
    expect(protocolPrivacyGuidance('tcp-md5').label).toBe('TCP MD5')
    expect(protocolPrivacyGuidance('dhcpv4-option').id).toBe('dhcpv4')
    expect(protocolPrivacyGuidance('dhcpv6-option').id).toBe('dhcpv6')
    expect(protocolPrivacyGuidance('mdns').label).toBe('mDNS')
    expect(protocolPrivacyGuidance('dns').label).toBe('DNS')
  })

  it('lists each detected protocol within a family, merges its fields and does not invent absent protocols', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [
        row({ protocol: 'udp', familyId: 'network-headers' }),
        row({ protocol: 'ipv4', familyId: 'network-headers' }),
        row({ protocol: 'ipv4-ttl', familyId: 'network-headers' }),
        row({ protocol: 'h248', familyId: 'sip' }),
      ], gate: 'AI_READY', plan: minimalPlan(), preset: 'diagnostic',
    })
    const network = outcome.families.find(f => f.familyId === 'network-headers')!
    expect(network.protocols.map(p => p.id).sort()).toEqual(['ipv4', 'udp'])
    expect(network.protocols.find(p => p.id === 'udp')?.check).toContain('sama nechrání')
    expect(outcome.families.find(f => f.familyId === 'sip')?.protocols.map(p => p.id)).toEqual(['h248'])
    expect(network.protocols.some(p => p.id === 'tcp')).toBe(false)
  })

  it('never gives a green outcome when a DMR voice subregion is exposed, even with a coarse green gate', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [row({ protocol: 'dmr', familyId: 'dmr' }), row({ protocol: 'dmr-voice', familyId: 'dmr',
        dominantStatus: 'preserved-unsafe', dominantUiStatus: 'exposed', userVerdict: 'recognized-risk-diagnostic' })],
      gate: 'AI_READY', plan: minimalPlan(), preset: 'diagnostic',
    })
    expect(outcome.gate).toBe('NOT_AI_READY')
    expect(outcome.families[0]?.protocols).toHaveLength(1)
    expect(outcome.families[0]?.protocols[0]?.check).toContain('AMBE hlas')
    expect(outcome.families[0]?.protocols[0]?.state).toBe('needs-attention')
  })

  it.each(['dmr', 'http'] as const)('retains specific %s warnings when the same protocol has an incident', protocol => {
    const incident = { unit: 'packet' as const, sourceId: 't', packetNumber: 1, protocol, stage: 'plan' as const,
      reason: 'sanitizer-exception' as const, fallback: 'packet-masked' as const }
    const outcome = buildAnonymizationOutcome({
      protocols: [row({ protocol, familyId: protocol,
        dominantStatus: protocol === 'dmr' ? 'preserved-unsafe' : 'heuristic',
        userVerdict: protocol === 'dmr' ? 'recognized-risk-diagnostic' : 'heuristic' })],
      gate: 'AI_READY', preset: 'diagnostic', plan: minimalPlan({ incidents: {
        ...EMPTY_INCIDENT_LOG_SNAPSHOT, totalFailures: 100, incidents: Array.from({ length: 100 }, () => incident),
      } }),
    })
    const detail = outcome.families[0]?.protocols[0]
    expect(detail?.check).toContain(protocol === 'dmr' ? 'AMBE hlas' : 'zbývající text')
    expect(detail?.check).toContain('incidenty')
    expect(detail?.check.match(/Otevřete incidenty/g)).toHaveLength(1)
    expect(outcome.gate).toBe('NOT_AI_READY')
  })

  it('does not claim exposed RTP voice was masked', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [row({ protocol: 'rtp', familyId: 'rtp-rtcp', dominantStatus: 'preserved-unsafe', userVerdict: 'recognized-risk-diagnostic' })],
      gate: 'NOT_AI_READY', plan: minimalPlan(), preset: 'diagnostic',
    })
    expect(outcome.families[0]?.protocols[0]?.method).toContain('nelze potvrdit')
    expect(outcome.families[0]?.protocols[0]?.method).not.toContain('maskujeme')
  })

  it.each([false, true])('keeps heuristic review advice after merging covered HTTP fields (heuristic first: %s)', first => {
    const covered = row({ protocol: 'http', familyId: 'http' })
    const heuristic = row({ protocol: 'http-body', familyId: 'http', dominantStatus: 'heuristic', userVerdict: 'heuristic' })
    const outcome = buildAnonymizationOutcome({
      protocols: first ? [heuristic, covered] : [covered, heuristic],
      gate: 'AI_READY_WITH_GAPS', plan: minimalPlan(), preset: 'diagnostic',
    })
    expect(outcome.gate).toBe('NOT_AI_READY')
    expect(outcome.families[0]?.protocols[0]?.needsReview).toBe(true)
    expect(outcome.families[0]?.protocols[0]?.method).toContain('heuristikou')
    expect(outcome.families[0]?.protocols[0]?.check).toContain('zbývající text')
  })

  it('does not describe masked unknown content as fully analyzed or absolutely anonymous', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [row({ protocol: 'payload', familyId: 'other', dominantStatus: 'redacted' })],
      gate: 'AI_READY', plan: minimalPlan(), preset: 'diagnostic',
    })
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.families[0]?.state).toBe('masked-without-analysis')
    expect(JSON.stringify(outcome)).not.toMatch(/100\s*%|stoprocent|důvěryhodně anonymní/i)
  })

  it('keeps encrypted content separate from content analysis, with exposed status taking precedence', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [row({ protocol: 'tls-encrypted-payload', familyId: 'tls', dominantStatus: 'encrypted',
        dominantUiStatus: 'exposed', userVerdict: 'encrypted-preserved' })],
      gate: 'AI_READY', plan: minimalPlan(), preset: 'diagnostic',
    })
    expect(outcome.gate).toBe('NOT_AI_READY')
    expect(outcome.families[0]?.state).toBe('needs-attention')
  })
  it.each(['covered', 'truncated'] as const)('uses actual sanitizer disposition for %s without legacy decode spans', status => {
    const outcome = buildAnonymizationOutcome({
      protocols: [row({ protocol: 'sip', familyId: 'sip', layerKind: 'sanitizer', dominantStatus: status,
        userVerdict: 'protected-export-no-full-analysis' })],
      gate: 'AI_READY', plan: minimalPlan(), preset: 'diagnostic',
    })
    expect(outcome.families[0]!.state).toBe(status === 'covered' ? 'anonymized' : 'masked-without-analysis')
  })
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

  it('T11 MGCP covered family is Anonymizováno (not masked-without-analysis)', () => {
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

describe('masked and redacted content is not reported as left readable', () => {
  const summary = (protocol: string, dominantStatus: UnifiedProtocolSummary['dominantStatus'], structural: boolean) => ({
    protocol, packetCount: 5, spanCount: 5, unsupportedCount: dominantStatus === 'unsupported' ? 5 : 0,
    structuralSpanCount: structural ? 5 : 0, sanitizerSpanCount: structural ? 0 : 5, dominantStatus, issues: [],
  })
  // Shape of a radio-gateway capture: masked ARP padding/ICMP echo, unknown ethertype payload,
  // Proprietary radio-protocol SIP body, masked LLDP/syslog bodies.
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

  it.each(['diagnostic', 'high-privacy'] as const)('%s: no protocol needs attention, gate keeps gaps', (preset) => {
    const outcome = buildAnonymizationOutcome({
      protocols: coverageRowsFromProtocolSummaries(summaries, preset),
      gate: 'AI_READY', plan: minimalPlan(), preset,
    })
    const flagged = outcome.families.flatMap((f) => f.protocols).filter((p) => p.needsReview || p.state === 'needs-attention')
    expect(flagged.map((p) => p.id)).toEqual([])
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.families.find((f) => f.familyId === 'dmr')?.state).toBe('anonymized')
  })

  it('has structured guidance for the radio-protocol SIP body', () => {
    const guide = protocolPrivacyGuidance('radio-protocol-body')
    expect(guide.known).toBe(true)
    expect(guide.method).toContain('maskujeme')
  })

  it('keeps flagging detector-only (heuristic) rows for review', () => {
    // Reassembly overlays (e.g. HTTP bodies) export detector-only text as is, so 'heuristic'
    // stays a review verdict; sanitizers that mask free text themselves report 'redacted'.
    const outcome = buildAnonymizationOutcome({
      protocols: coverageRowsFromProtocolSummaries([summary('http-body', 'heuristic', false)], 'diagnostic'),
      gate: 'AI_READY', plan: minimalPlan(), preset: 'diagnostic',
    })
    expect(outcome.gate).toBe('NOT_AI_READY')
    expect(outcome.families[0]?.protocols[0]?.needsReview).toBe(true)
  })

  it('flags heuristic text for review when the export would keep it', () => {
    const outcome = buildAnonymizationOutcome({
      protocols: [row({ protocol: 'syslog', familyId: 'logging', dominantStatus: 'heuristic', userVerdict: 'heuristic' })],
      gate: 'AI_READY', plan: minimalPlan(), preset: 'diagnostic',
    })
    expect(outcome.gate).toBe('NOT_AI_READY')
    expect(outcome.families[0]?.protocols[0]?.needsReview).toBe(true)
  })
})

describe('buildAnonymizationOutcomeForExport', () => {
  it.each(['AI_READY', 'AI_READY_WITH_GAPS', 'NOT_AI_READY'] as const)('preserves the final verified export gate %s in diagnostics and nested outcome', gate => {
    const manifest = buildAiDiagnosticsManifest({
      plan: minimalPlan(), gate,
      protocolCoverage: [{ protocol: 'http-body', packetCount: 1, spanCount: 1, unsupportedCount: 0,
        structuralSpanCount: 0, sanitizerSpanCount: 1, dominantStatus: 'heuristic', issues: [] }],
    })
    expect(manifest.gate).toBe(gate)
    expect(manifest.anonymizationOutcome.verdict).toBe(gate)
    expect(manifest.safeForAi).toBe(gate === 'AI_READY')
  })
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
