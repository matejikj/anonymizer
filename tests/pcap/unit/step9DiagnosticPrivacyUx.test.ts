/**
 * Step 9 — diagnostika vs. soukromí UX: card copy, summaries, safe errors, disposition.
 */

import { describe, expect, it } from 'vitest'
import { cs } from '../../../src/i18n/cs.ts'
import { createPresetProfile, DEFAULT_PCAP_PRESET } from '../../../src/pcap/profile/presets'
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import {
  buildPcapCoverageViewModel,
  spanExportAction,
} from '../../../src/pcap/coverage/pcapCoverageViewModel'
import { PlanInvariantError } from '../../../src/pcap/plan/planErrors'
import { formatPlanInvariantForUser } from '../../../src/pcap/ui/formatPlanError'
import { emptyPlanAuditFields } from '../../../src/pcap/plan/planDisposition'

function emptyPlan() {
  return {
    generationId: 'g1',
    profileId: 'p',
    profileHash: 'h',
    format: CaptureFormat.ClassicPcap,
    fileName: 'x.pcap',
    engineVersion: '1',
    packets: [],
    droppedPacketNumbers: [],
    timestamps: 'relative' as const,
    timestampAnchorSeed: 'test-anchor-seed',
    ...emptyPlanAuditFields(),
  }
}

function modelFromProtocol() {
  return {
    perPacket: [[]],
    byProtocol: [
      {
        protocol: 'dns',
        packetCount: 1,
        spanCount: 1,
        structuralSpanCount: 0,
        sanitizerSpanCount: 1,
        unsupportedCount: 0,
        dominantStatus: 'covered' as const,
      },
    ],
    histogram: new Map([['dns', 1]]),
    totalUnsupportedSpans: 0,
    totalHeuristicSpans: 0,
  }
}

describe('step 9 diagnostic card copy', () => {
  it('names the default preset Diagnostické pro AI — doporučeno', () => {
    expect(DEFAULT_PCAP_PRESET).toBe('diagnostic')
    expect(cs.pcap.presets.diagnosticName).toBe('Diagnostické pro AI — doporučeno')
    expect(cs.pcap.presets.defaultPresetBadge).toBe('doporučeno')
    expect(cs.pcap.presets.diagnosticImpact).toBe(
      'Zachová pakety, timing a protokolové chyby; identity mapuje a tajemství/média maskuje. Jde o diagnostickou pseudonymizaci, ne nevratnou anonymizaci.',
    )
    expect(createPresetProfile('diagnostic').name).toBe('Diagnostické pro AI — doporučeno')
  })
})

describe('step 9 pre-export summaries', () => {
  it('exposes three buckets for diagnostic overview/confirm', () => {
    const vm = buildPcapCoverageViewModel({
      unifiedCoverage: modelFromProtocol(),
      policy: DIAGNOSTIC_POLICY,
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
    expect(vm.summary.preExportSummaries.map((b) => b.id)).toEqual(['removed', 'kept', 'blocked'])
    expect(vm.summary.preExportSummaries[0]!.title).toBe(cs.pcap.coverageUx.summaryRemovedTitle)
    expect(vm.summary.preExportSummaries[1]!.title).toBe(cs.pcap.coverageUx.summaryKeptTitle)
    expect(vm.summary.preExportSummaries[2]!.title).toBe(cs.pcap.coverageUx.summaryBlockedTitle)
    expect(vm.summary.residualNote).toContain('korelovatelné')
    expect(vm.summary.exportLooksSafe).toBe(true)
    expect(vm.summary.primaryAction).toBe('export-safe')
  })

  it('requires confirm when anonymization is exposed', () => {
    const vm = buildPcapCoverageViewModel({
      unifiedCoverage: modelFromProtocol(),
      policy: DIAGNOSTIC_POLICY,
      plan: emptyPlan(),
      statuses: {
        anonymization: 'exposed',
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
    expect(vm.summary.exportLooksSafe).toBe(false)
    expect(vm.summary.primaryAction).toBe('confirm-exposed')
  })
})

describe('step 9 field disposition labels', () => {
  it('classifies mapped / redacted / masked / preserved-for-diagnostics', () => {
    expect(spanExportAction('covered')).toBe('mapped')
    expect(spanExportAction('redacted', { protocol: 'sip' })).toBe('redacted')
    expect(spanExportAction('redacted', { protocol: 'rtp' })).toBe('masked-content')
    expect(spanExportAction('preserved-for-diagnostics')).toBe('preserved-for-diagnostics')
    expect(cs.pcap.coverageUx.exportAction.mapped).toBe('mapováno')
    expect(cs.pcap.coverageUx.exportAction['masked-content']).toBe('payload maskován')
    expect(cs.pcap.coverageUx.exportAction['preserved-for-diagnostics']).toBe(
      'zachováno pro diagnostiku',
    )
  })
})

describe('step 9 safe mapping errors', () => {
  it('formats PlanInvariantError without original values', () => {
    const err = new PlanInvariantError({
      code: 'mapping-closure',
      message: 'Missing mapping alias for category=ipv4 at packetIndex=3 packetNumber=4',
      packetIndex: 3,
      packetNumber: 4,
      category: 'ipv4',
      canonical: '192.168.99.1',
    })
    const text = formatPlanInvariantForUser(err)
    expect(text).toContain('4')
    expect(text).toContain('ipv4')
    expect(text).not.toContain('192.168.99.1')
    expect(text).not.toContain('canonical')
  })
})

describe('step 9 export toast copy', () => {
  it('exposes a success toast string', () => {
    expect(cs.pcap.export.toastSuccess).toMatch(/export/i)
  })
})
