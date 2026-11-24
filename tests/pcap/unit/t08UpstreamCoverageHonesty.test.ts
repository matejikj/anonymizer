/**
 * T08.upstream — export gate reads sanitizer coverage on production paths;
 * fail-closed spans must not count as exposed; R02 must not emit spurious `encrypted`.
 */

import { describe, expect, it } from 'vitest'
import {
  buildGateChecksFromCoverage,
  resolveExportGate,
  summarizeSanitizationCoverage,
} from '../../../src/pcap/trust'
import type { PcapAnonymizationLevel } from '../../../src/pcap/profile/presets'
import { presetToSanitizationPolicy } from '../../../src/pcap/profile/presets'
import {
  resolveCoverageDisposition,
  type CoverageLayerKind,
} from '../../../src/pcap/sanitize/coverageDisposition'
import type { LayerCoverage } from '../../../src/pcap/sanitize/types'
import { runExportPipeline, type DiagnosticPipelineResult } from '../helpers/diagnosticPipeline'
import { voipCorpusScenarios, buildEthIpUdp, envelope } from '../fixtures/voipCorpus'
import { mgcpCorpusScenarios } from '../fixtures/mgcpCorpus'

const FAIL_CLOSED_DISPOSITIONS = new Set([
  'mask-in-place',
  'mask-application-in-place',
  'truncate',
  'drop',
  'strip-media-payload',
])

const R02_UNPROVEN_PROTOCOL_PREFIXES = ['dtls-app', 'dtls-ccs', 'quic-', 'openvpn-data', 'wireguard-']

function layerKindFor(protocol: string): CoverageLayerKind {
  const p = protocol.toLowerCase()
  if (p === 'rtp' || p === 'rtcp' || p === 'srtp' || p === 'media' || p === 'voip-media') {
    return 'media'
  }
  return 'application'
}

function assertSanitizerSpansHonest(coverage: readonly LayerCoverage[], level: PcapAnonymizationLevel): void {
  const policy = presetToSanitizationPolicy(level)
  for (const span of coverage) {
    if (R02_UNPROVEN_PROTOCOL_PREFIXES.some((prefix) => span.protocol.startsWith(prefix))) {
      expect(span.status, `${span.protocol} must not claim encrypted without proof`).not.toBe('encrypted')
    }
    const disposition = resolveCoverageDisposition(policy, span.status, layerKindFor(span.protocol))
    if (
      span.status === 'unsupported'
      || span.status === 'heuristic'
      || span.status === 'malformed'
      || span.status === 'requires-reassembly'
    ) {
      expect(
        FAIL_CLOSED_DISPOSITIONS.has(disposition),
        `${span.protocol} ${span.status} → ${disposition}`,
      ).toBe(true)
    }
  }
}

function assertPipelineReportGateHonest(
  result: DiagnosticPipelineResult,
  level: PcapAnonymizationLevel,
): void {
  const coverage = result.discovery.packetDiscovery.flatMap((p) => p.coverage)
  const policy = presetToSanitizationPolicy(level)
  const summary = summarizeSanitizationCoverage({ plan: result.plan, coverage, policy })
  const checks = buildGateChecksFromCoverage({
    coverage: summary,
    leakHits: 0,
    verificationFatalErrors: 0,
    profile: level,
    diagnosticInvariantOk: true,
  })
  const gate = resolveExportGate({ profile: level, checks })
  const parsed = JSON.parse(result.reportJson) as {
    gate: string
    gateChecks: { failClosedRegions: number; exposedRegions: number }
  }
  expect(parsed.gate).toBe(gate.gate)
  expect(parsed.gateChecks.failClosedRegions).toBe(summary.failClosedRegions)
  expect(parsed.gateChecks.exposedRegions).toBe(summary.exposedRegions)
}

describe('T08.upstream sanitizer coverage → export gate (production paths)', () => {
  it('VoIP golden corpus: spans fail-closed or mapped; report gate matches disposition bookkeeping', () => {
    for (const scenario of voipCorpusScenarios()) {
      const result = runExportPipeline(
        scenario.packets,
        'diagnostic',
        `t08-upstream-${scenario.id}.pcap`,
        `t08-upstream-${scenario.id}`,
        { mappingSeed: `t08-${scenario.id}` },
      )
      const coverage = result.discovery.packetDiscovery.flatMap((p) => p.coverage)
      assertSanitizerSpansHonest(coverage, 'diagnostic')
      assertPipelineReportGateHonest(result, 'diagnostic')
      const parsed = JSON.parse(result.reportJson) as { gate: string }
      expect(['AI_READY', 'AI_READY_WITH_GAPS', 'NOT_AI_READY']).toContain(parsed.gate)
    }
  })

  it('MGCP structured UDP export stays AI_READY when sanitizer marks covered (not false unsupported gate)', () => {
    const packets = [mgcpCorpusScenarios.crcxSdp()]
    const result = runExportPipeline(packets, 'diagnostic', 't08-mgcp.pcap', 't08-mgcp', {
      mappingSeed: 't08-mgcp',
    })
    const coverage = result.discovery.packetDiscovery.flatMap((p) => p.coverage)
    assertSanitizerSpansHonest(coverage, 'diagnostic')
    const summary = summarizeSanitizationCoverage({ plan: result.plan, coverage })
    expect(summary.exposedRegions).toBe(0)
    const gate = resolveExportGate({
      profile: 'diagnostic',
      checks: buildGateChecksFromCoverage({
        coverage: summary,
        leakHits: 0,
        verificationFatalErrors: 0,
        profile: 'diagnostic',
        diagnosticInvariantOk: true,
      }),
    })
    expect(gate.gate).toBe('AI_READY')
  })

  it('DTLS AppData export path: unsupported + fail-closed → AI_READY_WITH_GAPS (R02/T08)', () => {
    const canary = 'T08-UPSTREAM-DTLS-PLAINTEXT'
    const body = new Uint8Array(Array.from(canary, (c) => c.charCodeAt(0) & 0xff))
    const record = new Uint8Array(13 + body.length)
    record[0] = 0x17
    record[1] = 0xfe
    record[2] = 0xfd
    record[11] = (body.length >> 8) & 0xff
    record[12] = body.length & 0xff
    record.set(body, 13)
    const frame = envelope(buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 443, 443, record), 0)
    const result = runExportPipeline([frame], 'diagnostic', 't08-dtls.pcap', 't08-dtls', {
      mappingSeed: 't08-dtls',
    })
    const coverage = result.discovery.packetDiscovery.flatMap((p) => p.coverage)
    const app = coverage.find((c) => c.protocol === 'dtls-app')
    expect(app?.status).toBe('unsupported')
    assertSanitizerSpansHonest(coverage, 'diagnostic')
    const parsed = JSON.parse(result.reportJson) as { gate: string }
    expect(parsed.gate).toBe('AI_READY_WITH_GAPS')
  })
})
