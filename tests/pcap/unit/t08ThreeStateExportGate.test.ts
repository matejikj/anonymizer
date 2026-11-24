/**
 * T08 — three-state export gate by resulting disposition (not raw span status).
 */

import { describe, expect, it } from 'vitest'
import {
  buildGateChecksFromCoverage,
  resolveExportGate,
  resolveTextExportGate,
  summarizeSanitizationCoverage,
  worstGateResult,
} from '../../../src/pcap/trust'
import type { PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import type { LayerCoverage } from '../../../src/pcap/sanitize/types'
import { DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/profile/presets'

function emptyPlan(level: PcapPlanSnapshot['pcapLevel'] = 'diagnostic'): PcapPlanSnapshot {
  return {
    generationId: 'g-t08',
    pcapLevel: level,
    profileId: `pcap-${level}`,
    profileHash: 'hash',
    format: CaptureFormat.ClassicPcap,
    fileName: 't08.pcap',
    engineVersion: 'test',
    packets: [],
    droppedPacketNumbers: [],
    timestamps: level === 'diagnostic' ? 'relative' : 'enumerated',
    timestampAnchorSeed: 'test-anchor-seed',
    changeCategoryTotals: {
      mapped: 1,
      redacted: 0,
      'masked-content': 2,
      'preserved-encrypted': 0,
      'preserved-for-diagnostics': 0,
      'user-requested-drop': 0,
      blocked: 0,
    },
    maskedByteCount: 64,
    dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
    dropsByProtocol: {},
  }
}

function gateFromCoverage(
  coverage: LayerCoverage[],
  level: PcapPlanSnapshot['pcapLevel'] = 'diagnostic',
  extras?: { leakHits?: number; incidentCount?: number },
) {
  const plan = emptyPlan(level)
  const summary = summarizeSanitizationCoverage({
    plan,
    coverage,
    policy: level === 'diagnostic' ? DIAGNOSTIC_POLICY : HIGH_PRIVACY_POLICY,
    incidentCount: extras?.incidentCount,
  })
  const checks = buildGateChecksFromCoverage({
    coverage: summary,
    leakHits: extras?.leakHits ?? 0,
    verificationFatalErrors: 0,
    profile: level,
    diagnosticInvariantOk: true,
  })
  return { summary, outcome: resolveExportGate({ profile: level, checks }) }
}

describe('T08 three-state export gate', () => {
  it('DTLS unproven AppData span (unsupported) is AI_READY_WITH_GAPS after mask (T08/R02)', () => {
    const { summary, outcome } = gateFromCoverage([
      { protocol: 'dtls-app', offset: 0, length: 64, status: 'unsupported' },
    ])
    expect(summary.failClosedRegions).toBe(1)
    expect(summary.exposedRegions).toBe(0)
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
  })

  it('spurious encrypted status alone does not block export (must pair with exposed disposition)', () => {
    const { summary, outcome } = gateFromCoverage([
      { protocol: 'dtls-app', offset: 0, length: 64, status: 'encrypted' },
    ])
    expect(summary.exposedRegions).toBe(0)
    expect(summary.failClosedRegions).toBe(0)
    expect(outcome.gate).toBe('AI_READY')
  })

  it('masked unsupported and heuristic are AI_READY_WITH_GAPS (MGCP-like)', () => {
    const { summary, outcome } = gateFromCoverage([
      { protocol: 'mgcp', offset: 0, length: 32, status: 'heuristic' },
      { protocol: 'mgcp', offset: 32, length: 16, status: 'unsupported' },
      { protocol: 'sdp', offset: 48, length: 24, status: 'heuristic' },
    ])
    expect(summary.failClosedRegions).toBe(3)
    expect(summary.exposedRegions).toBe(0)
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.exportAllowed).toBe(true)
    expect(outcome.safeForAi).toBe(false)
  })

  it('requires-reassembly under diagnostic is fail-closed gaps, not NOT_AI_READY', () => {
    const { outcome } = gateFromCoverage([
      { protocol: 'tcp', offset: 0, length: 40, status: 'requires-reassembly' },
    ])
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.exportAllowed).toBe(true)
  })

  it('preserved-unsafe residual is AI_READY_WITH_GAPS (T67 — exportable, no ack)', () => {
    const { summary, outcome } = gateFromCoverage([
      { protocol: 'http-body', offset: 0, length: 12, status: 'preserved-unsafe' },
    ])
    expect(summary.exposedRegions).toBe(1)
    expect(summary.secretPassthroughBytes).toBe(12)
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.exportAllowed).toBe(true)
  })

  it('leak hits force AI_READY_WITH_GAPS even when spans are clean (T67)', () => {
    const { outcome } = gateFromCoverage(
      [{ protocol: 'ipv4', offset: 0, length: 4, status: 'covered' }],
      'diagnostic',
      { leakHits: 1 },
    )
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.exportAllowed).toBe(true)
  })

  it('clean coverage is AI_READY for both profiles', () => {
    expect(
      gateFromCoverage([{ protocol: 'ipv4', offset: 0, length: 4, status: 'covered' }], 'diagnostic')
        .outcome.gate,
    ).toBe('AI_READY')
    expect(
      gateFromCoverage([{ protocol: 'ipv4', offset: 0, length: 4, status: 'covered' }], 'high-privacy')
        .outcome.gate,
    ).toBe('AI_READY')
  })

  it('encrypted (preserve-encrypted) is AI_READY — not exposed, not a blocking gap', () => {
    const { summary, outcome } = gateFromCoverage([
      { protocol: 'tls', offset: 0, length: 64, status: 'encrypted' },
    ])
    expect(summary.exposedRegions).toBe(0)
    expect(summary.failClosedRegions).toBe(0)
    expect(outcome.gate).toBe('AI_READY')
    expect(outcome.exportAllowed).toBe(true)
  })

  it('processing-failed isolation regions are gaps (export allowed), not NOT_AI_READY', () => {
    const { outcome } = gateFromCoverage([
      { protocol: 'processing-failed', offset: 14, length: 50, status: 'processing-failed' },
    ], 'diagnostic', { incidentCount: 1 })
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.exportAllowed).toBe(true)
  })

  it('incidentCount alone yields AI_READY_WITH_GAPS', () => {
    const { outcome } = gateFromCoverage(
      [{ protocol: 'ipv4', offset: 0, length: 4, status: 'covered' }],
      'diagnostic',
      { incidentCount: 2 },
    )
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.exportAllowed).toBe(true)
  })

  it('text: failed rules / incidents → WITH_GAPS; exposedEntityCount ignored (T71); clean → AI_READY', () => {
    expect(
      resolveTextExportGate({ failedRuleIds: ['r1'], incidentCount: 0, exposedEntityCount: 0 }).gate,
    ).toBe('AI_READY_WITH_GAPS')
    expect(
      resolveTextExportGate({ failedRuleIds: [], incidentCount: 3, exposedEntityCount: 0 }).gate,
    ).toBe('AI_READY_WITH_GAPS')
    expect(
      resolveTextExportGate({ failedRuleIds: [], incidentCount: 0, exposedEntityCount: 2 }).gate,
    ).toBe('AI_READY')
    expect(
      resolveTextExportGate({ failedRuleIds: [], incidentCount: 0, exposedEntityCount: 0 }).gate,
    ).toBe('AI_READY')
  })

  it('worstGateResult aggregates correlation sources', () => {
    expect(worstGateResult('AI_READY', 'AI_READY_WITH_GAPS')).toBe('AI_READY_WITH_GAPS')
    expect(worstGateResult('AI_READY_WITH_GAPS', 'NOT_AI_READY')).toBe('NOT_AI_READY')
    expect(worstGateResult('AI_READY', 'NOT_AI_READY')).toBe('NOT_AI_READY')
  })
})
