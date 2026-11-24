/**
 * Stage 6 integration — Overview / Coverage / strip / detail / export share planRevision.
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import {
  buildPcapCoverageViewModel,
  buildPlanRevision,
} from '../../src/pcap/coverage/pcapCoverageViewModel'
import type { UnifiedCoverageModel } from '../../src/pcap/coverage/types'
import type { SanitizationPolicy } from '../../src/pcap/sanitize/types'
import type { PcapPlanSnapshot } from '../../src/pcap/export/planSnapshot'
import { DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../src/pcap/sanitize'

function policy(preset: SanitizationPolicy['preset']): SanitizationPolicy {
  if (preset === 'high-privacy') return HIGH_PRIVACY_POLICY
  return DIAGNOSTIC_POLICY
}

function coverage(): UnifiedCoverageModel {
  return {
    perPacket: [
      [
        {
          packetIndex: 0,
          protocol: 'dns',
          source: 'sanitizer',
          offset: 0,
          length: 4,
          status: 'covered',
          issues: [],
        },
      ],
    ],
    byProtocol: [
      {
        protocol: 'dns',
        packetCount: 1,
        spanCount: 1,
        unsupportedCount: 0,
        structuralSpanCount: 0,
        sanitizerSpanCount: 1,
        dominantStatus: 'covered',
        issues: [],
      },
    ],
    histogram: new Map([['dns', 1]]),
    totalUnsupportedSpans: 0,
    totalTruncatedSpans: 0,
    totalHeuristicSpans: 0,
  }
}

function plan(hash: string, packets = 1): PcapPlanSnapshot {
  return {
    generationId: 'gen',
    profileId: 'p',
    profileHash: hash,
    format: 0,
    fileName: 't.pcap',
    engineVersion: '1',
    packets: Array.from({ length: packets }, (_, i) => ({
      index: i,
      packetNumber: i + 1,
      drop: false,
      patches: [],
      originalCapturedLength: 64,
      originalLength: 64,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      originalTimestamp: { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    })),
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

const statuses = {
  anonymization: 'covered' as const,
  integrity: 'ok' as const,
  compatibility: 'valid' as const,
  truncatedCount: 0,
  unsupportedCount: 0,
  droppedCount: 0,
  changedCount: 1,
  reassemblyCount: 0,
  issueCount: 0,
}

describe('Stage 6 coverage plan revision consistency', () => {
  it('rebuild with new profileHash publishes a new shared planRevision', () => {
    const before = buildPcapCoverageViewModel({
      unifiedCoverage: coverage(),
      policy: policy('high-privacy'),
      plan: plan('hash-hp'),
      statuses,
      generationId: 'gen',
      mappingRevision: 1,
      profileHash: 'hash-hp',
    })
    const after = buildPcapCoverageViewModel({
      unifiedCoverage: coverage(),
      policy: policy('diagnostic'),
      plan: plan('hash-diag'),
      statuses,
      generationId: 'gen',
      mappingRevision: 2,
      profileHash: 'hash-diag',
    })
    expect(before.planRevision).not.toBe(after.planRevision)
    expect(after.planRevision).toBe(
      buildPlanRevision({
        generationId: 'gen',
        mappingRevision: 2,
        profileHash: 'hash-diag',
        planPacketCount: 1,
      }),
    )
    // Surfaces that stamp data-plan-revision must all equal after.planRevision
    expect(after.protocols[0]!.userVerdict).toBe('recognized-and-protected')
    expect(after.spansForPacket(0)[0]!.exportActionLabel).toBe('mapováno')
    // Step 7/9: diagnostic fingerprint residuals are intentional — export looks safe
    expect(after.summary.exportLooksSafe).toBe(true)
  })

  it('exposed session never reports exportLooksSafe', () => {
    const vm = buildPcapCoverageViewModel({
      unifiedCoverage: coverage(),
      policy: policy('diagnostic'),
      plan: plan('addr'),
      statuses: { ...statuses, anonymization: 'exposed', unsupportedCount: 1 },
      generationId: 'gen',
      mappingRevision: 5,
      profileHash: 'addr',
    })
    expect(vm.summary.exportLooksSafe).toBe(false)
    expect(vm.summary.primaryAction).toBe('confirm-exposed')
  })
})
