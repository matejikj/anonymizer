/**
 * R10 packed-discover honesty: the UI thread has no per-packet coverage rows, so export
 * bookkeeping / privacy report / correlation gate must use the weighted worker rollup, and
 * the journal u16/u32 encoders must fail closed (mask + incident) on unrepresentable aliases.
 * Synthetic data only.
 */

import { describe, expect, it } from 'vitest'
import { IncidentLog } from '../../../src/domain/anonymizationIncident'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { formatPortTextFromWire } from '../../../src/pcap/anonymization/wireTextFormat'
import type { MappingLike } from '../../../src/pcap/anonymization/mapping'
import type { PacketDiscoveryResult } from '../../../src/pcap/discovery/types'
import { renderSymbolicOperations, type SymbolicOperation } from '../../../src/pcap/kernel'
import { countPreservedUnsafeSpans } from '../../../src/pcap/privacy/privacyReport'
import {
  coverageRollupFromDiscovery,
  discoveryIssuesForExport,
  sanitizerCoverageForExport,
} from '../../../src/pcap/processing/packedCaptureWire'
import type { LayerCoverage } from '../../../src/pcap/sanitize/types'
import {
  ROLLUP_MAX_COVERAGE_KINDS,
  ROLLUP_MAX_ISSUE_TOKENS,
  ROLLUP_MAX_ISSUE_TOKENS_HARD,
  mergeCoverageRollup,
  packPacketDiscovery,
} from '../../../src/pcap/processing/packedCaptureWire'
import { computeStatusesFromDiscovery, createMinimalPcapSession } from '../../../src/pcap/ui/pcapSession'
import { buildPcapCoverageViewModel } from '../../../src/pcap/coverage/pcapCoverageViewModel'
import { assessCorrelationSourceExport } from '../../../src/correlation/export/correlationExportSecurity'
import type { CorrelationSourceRecord } from '../../../src/correlation/types'
import { summarizeSanitizationCoverage } from '../../../src/pcap/trust/coverageBookkeeping'
import type { PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets'

function emptyPlan(): PcapPlanSnapshot {
  return {
    generationId: 'rollup',
    pcapLevel: 'diagnostic',
    profileId: 'rollup',
    profileHash: 'rollup',
    format: CaptureFormat.ClassicPcap,
    fileName: 'rollup.pcap',
    engineVersion: 'test',
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

function pd(index: number, coverage: LayerCoverage[], issues: string[] = []): PacketDiscoveryResult {
  return { packetIndex: index, packetNumber: index + 1, drop: false, issues, intents: [], coverage }
}

const DISCOVERY: PacketDiscoveryResult[] = [
  pd(0, [
    { protocol: 'sip', offset: 0, length: 10, status: 'preserved-unsafe' },
    { protocol: 'rtp', offset: 10, length: 20, status: 'preserved-unsafe' },
    { protocol: 'sigtran', offset: 30, length: 5, status: 'requires-reassembly' },
  ], ['tls-branch:ech']),
  pd(1, [
    { protocol: 'sip', offset: 0, length: 12, status: 'preserved-unsafe' },
    { protocol: 'http2', offset: 12, length: 4, status: 'malformed' },
    { protocol: 'udp', offset: 0, length: 8, status: 'covered' },
  ], ['tls-branch:ech', 'tls-branch:esni']),
]

describe('coverage rollup (packed discover)', () => {
  const rollup = coverageRollupFromDiscovery(DISCOVERY)

  it('counts each packet once across multiple statuses and protocols in one family', () => {
    const mixed = coverageRollupFromDiscovery([
      pd(0, [
        { protocol: 'sip', offset: 0, length: 10, status: 'covered' },
        { protocol: 'sip', offset: 10, length: 5, status: 'preserved-unsafe' },
        { protocol: 'sip-body', offset: 15, length: 5, status: 'redacted' },
      ]),
      pd(1, [{ protocol: 'sip-body', offset: 0, length: 10, status: 'redacted' }]),
    ])
    expect(mixed.protocolSummaries?.find(p => p.protocol === 'sip')).toMatchObject({
      packetCount: 1, familyPacketCount: 2, dominantStatus: 'preserved-unsafe', spanCount: 2,
    })
    expect(mixed.protocolSummaries?.find(p => p.protocol === 'sip-body')).toMatchObject({ packetCount: 2, familyPacketCount: 2 })
    const model = { perPacket: [], byProtocol: [], histogram: new Map(), totalUnsupportedSpans: 0, totalTruncatedSpans: 0, totalHeuristicSpans: 0 }
    const merged = mergeCoverageRollup(model, mixed)
    expect(mergeCoverageRollup(merged, mixed)).toEqual(merged)
    expect(merged.histogram.get('sip')).toBe(1)
  })

  it('counts reassembly/malformed spans and keeps distinct safe issue tokens', () => {
    expect(rollup.preservedUnsafeSpans).toBe(3)
    expect(rollup.requiresReassemblySpans).toBe(1)
    expect(rollup.malformedSpans).toBe(1)
    expect([...rollup.issueTokens].sort()).toEqual(['tls-branch:ech', 'tls-branch:esni'])
    // Aggregated per protocol × status — bounded by distinct ids, not by packet count.
    expect(rollup.coverageKinds).toHaveLength(5)
    expect(rollup.coverageKinds.find((k) => k.protocol === 'sip' && k.status === 'preserved-unsafe')).toMatchObject({
      count: 2,
      bytes: 22,
    })
  })

  it('weighted rollup coverage yields the same privacy/bookkeeping numbers as the real spans', () => {
    const real = sanitizerCoverageForExport(DISCOVERY, undefined)
    const packed = sanitizerCoverageForExport([], rollup)
    expect(countPreservedUnsafeSpans(packed)).toBe(countPreservedUnsafeSpans(real))
    expect(countPreservedUnsafeSpans(packed)).toBe(3)
    expect(discoveryIssuesForExport([], rollup).length).toBeGreaterThan(0)

    const plan = emptyPlan()
    const a = summarizeSanitizationCoverage({ plan, coverage: real, policy: DIAGNOSTIC_POLICY })
    const b = summarizeSanitizationCoverage({ plan, coverage: packed, policy: DIAGNOSTIC_POLICY })
    expect(b.exposedRegions).toBe(a.exposedRegions)
    expect(b.failClosedRegions).toBe(a.failClosedRegions)
    expect(b.secretPassthroughBytes).toBe(a.secretPassthroughBytes)
  })

  it('prefers real per-packet spans when they are present', () => {
    expect(sanitizerCoverageForExport(DISCOVERY, rollup)).toHaveLength(6)
  })
})

describe('journal integer encoders fail closed', () => {
  const op = (alias: string): { ops: SymbolicOperation[]; mapping: MappingLike } => ({
    ops: [
      {
        kind: 'map',
        packetIndex: 3,
        offset: 34,
        length: 2,
        category: 'port',
        canonical: 'udp/40000',
        constraint: { kind: 'port-wire', protocol: 'udp' },
        encoder: 'u16-be',
      },
    ],
    mapping: {
      overflow: false,
      map: () => alias,
      get: () => alias,
      aliasFor: () => alias,
    },
  })

  for (const alias of ['udp/not-a-number', 'udp/70000', '']) {
    it(`masks the field and records a value-free incident for alias "${alias}"`, () => {
      const { ops, mapping } = op(alias)
      const incidentLog = new IncidentLog()
      const patches = renderSymbolicOperations(ops, {
        mapping,
        fingerprints: new FingerprintSession('rollup-export-seed'),
        incidentLog,
        sourceId: 'synthetic',
      })
      expect(patches).toHaveLength(1)
      expect(patches[0]!.data).toHaveLength(2)
      const snap = incidentLog.snapshot()
      expect(snap.totalFailures).toBe(1)
      expect(snap.incidents[0]).toMatchObject({ unit: 'field', category: 'port', fallback: 'field-masked' })
      expect(JSON.stringify(snap)).not.toContain('40000')
    })
  }

  it('encodes a transport-qualified port alias as its number', () => {
    const { ops, mapping } = op('udp/49154')
    const patches = renderSymbolicOperations(ops, {
      mapping,
      fingerprints: new FingerprintSession('rollup-export-seed'),
    })
    expect(Array.from(patches[0]!.data)).toEqual([0xc0, 0x02])
  })
})

describe('formatPortTextFromWire folding', () => {
  it('never folds back onto the original port number', () => {
    // 5-digit wire alias folded into a 4-digit text slot (span 1024..9999 = 8976 values).
    const SPAN = 9999 - 1024 + 1
    for (const original of ['5070', '5092', '1024', '9999']) {
      const originalPort = Number.parseInt(original, 10)
      // Wire values whose plain fold lands exactly on the original — the dangerous ones.
      const colliding: number[] = []
      for (let w = originalPort - 1024; w <= 49_151; w += SPAN) if (w >= 10_000) colliding.push(w)
      expect(colliding.length).toBeGreaterThan(0)
      const coarse = Array.from({ length: 400 }, (_, i) => 10_000 + i * 98)
      for (const wire of [...colliding, ...coarse]) {
        const text = formatPortTextFromWire(wire, original)
        expect(text).toHaveLength(original.length)
        expect(Number.parseInt(text, 10)).not.toBe(originalPort)
        expect(Number.parseInt(text, 10)).toBeGreaterThanOrEqual(1024)
      }
    }
  })
})

describe('rollup bounds', () => {
  it('collapses packet-derived protocol ids past the cap but keeps status and exact ids', () => {
    const discovery: PacketDiscoveryResult[] = []
    const n = ROLLUP_MAX_COVERAGE_KINDS + 300
    for (let i = 0; i < n; i++) {
      discovery.push(pd(i, [{ protocol: `sctp-ppid-${i}`, offset: 0, length: 4, status: 'preserved-unsafe' }]))
    }
    // Exact ids arriving after the cap must stay exact (disposition depends on them).
    discovery.push(pd(n, [
      { protocol: 'rtp', offset: 0, length: 9, status: 'preserved-unsafe' },
      { protocol: 'tls-clienthello', offset: 0, length: 9, status: 'covered' },
    ]))
    const rollup = coverageRollupFromDiscovery(discovery)
    expect(rollup.coverageKinds.length).toBeLessThanOrEqual(ROLLUP_MAX_COVERAGE_KINDS + 3)
    expect(rollup.protocolSummaries!.length).toBeLessThanOrEqual(ROLLUP_MAX_COVERAGE_KINDS + 3)
    expect(rollup.preservedUnsafeSpans).toBe(n + 1)
    const other = rollup.coverageKinds.find((k) => k.protocol === 'other' && k.status === 'preserved-unsafe')
    expect(other?.count).toBe(300)
    expect(rollup.coverageKinds.some((k) => k.protocol === 'rtp' && k.status === 'preserved-unsafe')).toBe(true)
    expect(rollup.coverageKinds.some((k) => k.protocol === 'tls-clienthello')).toBe(true)
    // Weighted total is unchanged by the folding.
    expect(countPreservedUnsafeSpans(coverageFromRollupForTest(rollup))).toBe(n + 1)
  })

  it('bounds issue tokens, folds packet-derived suffixes, keeps crypto/TLS-branch tokens', () => {
    const discovery: PacketDiscoveryResult[] = []
    for (let i = 0; i < ROLLUP_MAX_ISSUE_TOKENS_HARD + 500; i++) {
      discovery.push(pd(i, [], [`sctp-unknown-ppid:${i}`]))
    }
    discovery.push(pd(99_999, [], ['tls-branch:ech', 'crypto-integrity-modified:tls']))
    const rollup = coverageRollupFromDiscovery(discovery)
    expect(rollup.issueTokens.length).toBeLessThanOrEqual(ROLLUP_MAX_ISSUE_TOKENS_HARD + 4)
    expect(rollup.issueTokens).toContain('tls-branch:ech')
    expect(rollup.issueTokens).toContain('crypto-integrity-modified:tls')
    expect(rollup.issueTokens).toContain('sctp-unknown-ppid')
    expect(rollup.discoveryIssueCount).toBe(ROLLUP_MAX_ISSUE_TOKENS_HARD + 500 + 2)
    expect(ROLLUP_MAX_ISSUE_TOKENS).toBeLessThan(ROLLUP_MAX_ISSUE_TOKENS_HARD)
  })

  it('packPacketDiscovery reuses the single rollup implementation', () => {
    expect(packPacketDiscovery(DISCOVERY).coverageRollup).toEqual(coverageRollupFromDiscovery(DISCOVERY))
  })
})

function coverageFromRollupForTest(rollup: ReturnType<typeof coverageRollupFromDiscovery>): LayerCoverage[] {
  return sanitizerCoverageForExport([], rollup)
}

describe('statuses on the packed path (rollup branch)', () => {
  const base = createMinimalPcapSession({ fileName: 'rollup.pcap', fileSize: 0, format: CaptureFormat.ClassicPcap })
  const rollup = coverageRollupFromDiscovery(DISCOVERY)
  const statuses = (policy = base.policy) =>
    computeStatusesFromDiscovery({
      issues: [],
      analysis: base.analysis,
      packetDiscovery: [],
      unifiedCoverage: mergeCoverageRollup(base.unifiedCoverage, rollup),
      entityOccurrenceIndex: base.entityOccurrenceIndex,
      plan: base.plan,
      policy,
      coverageRollup: rollup,
    })

  it('preserved-unsafe spans in the rollup make the session exposed', () => {
    const s = statuses()
    expect(s.anonymization).toBe('exposed')
    expect(s.reassemblyCount).toBe(1)
    expect(s.issueCount).toBeGreaterThanOrEqual(1) // malformed span + discovery issue tokens
  })

  it('without the rollup the same empty discovery looks covered (the bug this guards)', () => {
    const s = computeStatusesFromDiscovery({
      issues: [],
      analysis: base.analysis,
      packetDiscovery: [],
      unifiedCoverage: base.unifiedCoverage,
      entityOccurrenceIndex: base.entityOccurrenceIndex,
      plan: base.plan,
      policy: base.policy,
    })
    expect(s.anonymization).toBe('covered')
  })
})

describe('gate preview never greener than the session statuses', () => {
  const base = createMinimalPcapSession({ fileName: 'gate.pcap', fileSize: 0, format: CaptureFormat.ClassicPcap })
  const vm = (sanitizerCoverage: readonly LayerCoverage[] | undefined, anonymization: 'covered' | 'exposed') =>
    buildPcapCoverageViewModel({
      sanitizerCoverage,
      unifiedCoverage: base.unifiedCoverage,
      policy: base.policy,
      plan: base.plan,
      statuses: {
        anonymization,
        integrity: 'ok',
        compatibility: 'valid',
        truncatedCount: 0,
        unsupportedCount: 0,
        droppedCount: 0,
        changedCount: 0,
        reassemblyCount: 0,
        heuristicCount: 0,
        issueCount: 0,
      },
      generationId: 'gate',
      mappingRevision: 1,
      profileHash: 'gate',
    })

  it('preserved-unsafe sanitizer coverage → NOT_AI_READY', () => {
    const unsafe = sanitizerCoverageForExport([], coverageRollupFromDiscovery(DISCOVERY))
    expect(vm(unsafe, 'exposed').summary.gateBadge).toBe('NOT_AI_READY')
  })

  it('exposed status alone never yields AI_READY', () => {
    expect(vm(undefined, 'exposed').summary.gateBadge).toBe('NOT_AI_READY')
  })

  it('clean coverage stays AI_READY', () => {
    expect(vm([], 'covered').summary.gateBadge).toBe('AI_READY')
  })
})

describe('correlation gate on a rollup-only source', () => {
  const base = createMinimalPcapSession({ fileName: 'corr.pcap', fileSize: 0, format: CaptureFormat.ClassicPcap })
  const record = (rollup: ReturnType<typeof coverageRollupFromDiscovery> | undefined) =>
    ({
      sourceId: 's1',
      kind: 'pcap',
      fileName: 'corr.pcap',
      outputFileName: 'corr.anonym.pcap',
      byteLength: 0,
      phase: 'planned',
      exportState: 'ready',
      textReview: null,
      discovery: {
        kind: 'pcap',
        policy: base.policy,
        discovery: {
          analysis: base.analysis,
          unifiedCoverage: base.unifiedCoverage,
          packetDiscovery: [],
        },
        container: { issues: [], coverageRollup: rollup },
      },
      plan: { kind: 'pcap', plan: base.plan },
    }) as unknown as CorrelationSourceRecord

  it('preserved-unsafe spans from the rollup → exposed', () => {
    expect(assessCorrelationSourceExport(record(coverageRollupFromDiscovery(DISCOVERY)))).toBe('exposed')
  })

  it('no rollup and no spans → not exposed', () => {
    expect(assessCorrelationSourceExport(record(undefined))).not.toBe('exposed')
  })
})

describe('formatPortTextFromWire edge cases', () => {
  it('small slots fold inside the slot and never return the original digits', () => {
    for (const original of ['102', '103', '104', '80', '5']) {
      for (let wire = 1000; wire <= 65_534; wire += 7) {
        const text = formatPortTextFromWire(wire, original)
        expect(text).toHaveLength(original.length)
        expect(text).not.toBe(original)
        expect(/^\d+$/.test(text)).toBe(true)
      }
    }
  })

  it('keeps a wire alias that fits the slot (preserved ports stay preserved)', () => {
    expect(formatPortTextFromWire(5070, '5070')).toBe('5070')
    expect(formatPortTextFromWire(80, '80')).toBe('80')
  })

  it('preserves non-digit shape and rejects non-integer aliases', () => {
    expect(formatPortTextFromWire(40000, ':5060')).toMatch(/^:\d{4}$/)
    for (const bad of [Number.NaN, -1, 1.5, Number.POSITIVE_INFINITY]) {
      expect(() => formatPortTextFromWire(bad, '5060')).toThrow()
    }
  })
})
