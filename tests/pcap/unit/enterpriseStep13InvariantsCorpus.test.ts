/**
 * Enterprise step 13 — golden / fuzz / invariant corpus aggregator.
 *
 * Mandatory acceptance:
 * - diagnostic: count/order/length/Δt preserved; sensitive tokens absent
 * - high-privacy: confirmed media DROP
 * - AI root-cause class preserved (SIP 403, one-way RTP, DNS NXDOMAIN, TCP RST/retransmit)
 * - TEST MODE deterministic seed → bit-identical aliases
 * - production path rejects fixed seed
 * - TCP split-at-every-byte / retransmit / OOO covered by enterpriseStep3 (cross-ref)
 */

import { describe, expect, it } from 'vitest'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import {
  buildDiagnosticFactModel,
} from '../../../src/pcap/diagnostics'
import {
  assertProductionMappingHasNoFixedSeed,
  createProductionSessionMapping,
  createTestSessionMapping,
  FORBIDDEN_PRODUCTION_DEFAULT_SEEDS,
} from '../../../src/pcap/anonymization'
import { levelToMappingConfig } from '../../../src/pcap/profile/presets'
import { runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline'
import { HIGH_PRIVACY_POLICY } from '../../../src/pcap/profile/presets'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import {
  DIAGNOSTIC_SEED_TOKENS,
  diagnosticIncidents,
} from '../fixtures/diagnosticIncidents'
import {
  runDiagnosticExportPipeline,
  runExportPipeline,
} from '../helpers/diagnosticPipeline'
import { buildEthIpUdp, envelope } from '../fixtures/voipCorpus'

const AI_ROOT_CAUSE_IDS = [
  'sip-register-failure', // SIP 403
  'rtp-one-way',
  'dns-nxdomain',
  'tcp-reset',
  'tcp-retransmission',
] as const

const TEST_SEED = 'enterprise-step13-test-seed-v1'

function latin1Decode(buf: Uint8Array): string {
  return Array.from(buf, (b) => String.fromCharCode(b)).join('')
}

function buildRtpPayload(ssrc: number, sequence: number, timestamp: number): Uint8Array {
  const buf = new Uint8Array(12 + 24)
  buf[0] = 0x80
  buf[1] = 0
  buf[2] = (sequence >> 8) & 0xff
  buf[3] = sequence & 0xff
  buf[4] = (timestamp >> 24) & 0xff
  buf[5] = (timestamp >> 16) & 0xff
  buf[6] = (timestamp >> 8) & 0xff
  buf[7] = timestamp & 0xff
  buf[8] = (ssrc >> 24) & 0xff
  buf[9] = (ssrc >> 16) & 0xff
  buf[10] = (ssrc >> 8) & 0xff
  buf[11] = ssrc & 0xff
  for (let i = 12; i < buf.length; i++) buf[i] = 0xa5
  return buf
}

function tickOf(p: PacketEnvelope): bigint {
  return p.timestamp.ticks
}

describe('enterprise step 13 — invariant / golden / fuzz corpus', () => {
  it('diagnostic preserves count/order/length/Δt on AI root-cause incidents', () => {
    const incidents = diagnosticIncidents()
    for (const id of AI_ROOT_CAUSE_IDS) {
      const incident = incidents.find((i) => i.id === id)
      expect(incident, id).toBeDefined()
      const { plan, built, packets } = runDiagnosticExportPipeline(
        incident!.packets,
        `s13-${id}.pcap`,
        `s13-${id}`,
      )
      expect(plan.droppedPacketNumbers.length, id).toBe(0)
      const reread = readClassicPcap(built.buffer)
      expect(reread.packets.length, id).toBe(packets.length)
      for (let i = 0; i < packets.length; i++) {
        expect(reread.packets[i]!.capturedLength, `${id}#${i}`).toBe(packets[i]!.capturedLength)
        expect(reread.packets[i]!.packetNumber, `${id}#${i}`).toBe(packets[i]!.packetNumber)
      }
      for (let i = 1; i < packets.length; i++) {
        const origDelta = tickOf(packets[i]!) - tickOf(packets[i - 1]!)
        const anonDelta = tickOf(reread.packets[i]!) - tickOf(reread.packets[i - 1]!)
        expect(anonDelta, `${id} Δt #${i}`).toBe(origDelta)
      }
    }
  })

  it('AI root-cause class is preserved after diagnostic sanitization', () => {
    const incidents = diagnosticIncidents()
    for (const id of AI_ROOT_CAUSE_IDS) {
      const incident = incidents.find((i) => i.id === id)!
      const { built, packets } = runDiagnosticExportPipeline(
        incident.packets,
        `s13-rc-${id}.pcap`,
        `s13-rc-${id}`,
      )
      const reread = readClassicPcap(built.buffer)
      const original = buildDiagnosticFactModel(packets, incident.rootCauseCategory)
      const anon = buildDiagnosticFactModel(
        reread.packets.map((p, i) => ({ ...p, packetNumber: packets[i]!.packetNumber })),
        incident.rootCauseCategory,
      )
      expect(anon.rootCauseCategory, id).toBe(original.rootCauseCategory)
      expect(anon.rootCauseCategory, id).toBe(incident.rootCauseCategory)
    }
  })

  it('sensitive seed tokens are absent from diagnostic export bytes + report', () => {
    const incident = diagnosticIncidents().find((i) => i.id === 'sip-register-failure')!
    const { built, reportJson, aiDiagnosticsJson } = runDiagnosticExportPipeline(
      incident.packets,
      's13-tokens.pcap',
      's13-tokens',
    )
    const wire = latin1Decode(new Uint8Array(built.buffer))
    for (const token of DIAGNOSTIC_SEED_TOKENS) {
      expect(wire.includes(token), `wire leaked ${token}`).toBe(false)
      expect(reportJson.includes(token), `report leaked ${token}`).toBe(false)
      expect(aiDiagnosticsJson.includes(token), `ai leaked ${token}`).toBe(false)
    }
  })

  it('high-privacy drops confirmed RTP media (policy DROP)', () => {
    const ssrc = 0x55aa55aa
    const packets: PacketEnvelope[] = [
      envelope(buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5004, 5006, buildRtpPayload(ssrc, 1, 160)), 0),
      envelope(buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5004, 5006, buildRtpPayload(ssrc, 2, 320)), 1),
      envelope(buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5004, 5006, buildRtpPayload(ssrc, 3, 480)), 2),
    ]
    // Discovery path confirms then drops (same MediaFlowIndex evidence as CF-03).
    const discovery = runDiscoveryPipeline(packets, HIGH_PRIVACY_POLICY, 's13-hp', 's13-hp.pcap')
    expect(discovery.packetDiscovery.some((p) => p.drop)).toBe(true)

    const { plan } = runExportPipeline(packets, 'high-privacy', 's13-hp.pcap', 's13-hp')
    expect(plan.droppedPacketNumbers.length).toBeGreaterThan(0)
    // First packet may be suspected-only; at least one confirmed packet must DROP.
    expect(plan.droppedPacketNumbers).toContain(1)
  })

  it('TEST MODE seed yields bit-identical aliases across sessions', () => {
    const config = levelToMappingConfig('diagnostic')
    const a = createTestSessionMapping(TEST_SEED, config)
    const b = createTestSessionMapping(TEST_SEED, config)
    const ips = ['10.1.2.3', '10.1.2.4', '192.168.9.9']
    const aliasesA = ips.map((ip) => a.map('ipv4', ip))
    const aliasesB = ips.map((ip) => b.map('ipv4', ip))
    expect(aliasesA).toEqual(aliasesB)
    expect(a.seeded).toBe(true)
    expect(a.map('ssrc', '305419896')).toBe(b.map('ssrc', '305419896'))
  })

  it('production mapping has no fixed seed; rejects production seed injection assert', () => {
    const prod = createProductionSessionMapping(levelToMappingConfig('diagnostic'))
    expect(prod.seeded).toBe(false)
    expect(() => assertProductionMappingHasNoFixedSeed({ seed: TEST_SEED })).toThrow(
      /TEST MODE only/,
    )
    expect(() => assertProductionMappingHasNoFixedSeed(undefined)).not.toThrow()
    for (const bad of FORBIDDEN_PRODUCTION_DEFAULT_SEEDS) {
      if (bad.length === 0) continue
      expect(() => createTestSessionMapping(bad)).toThrow()
    }
    expect(() => createTestSessionMapping('short')).toThrow(/≥ 8/)
  })

  it('same TEST MODE seed through export pipeline maps identities consistently', () => {
    const incident = diagnosticIncidents().find((i) => i.id === 'dns-nxdomain')!
    const r1 = runDiagnosticExportPipeline(
      incident.packets,
      's13-seed-a.pcap',
      's13-seed-a',
      { mappingSeed: TEST_SEED },
    )
    const r2 = runDiagnosticExportPipeline(
      incident.packets,
      's13-seed-b.pcap',
      's13-seed-b',
      { mappingSeed: TEST_SEED },
    )
    const aliases1 = r1.snapshot.entries
      .filter((e) => e.alias !== e.canonical)
      .map((e) => `${e.category}:${e.canonical}->${e.alias}`)
      .sort()
    const aliases2 = r2.snapshot.entries
      .filter((e) => e.alias !== e.canonical)
      .map((e) => `${e.category}:${e.canonical}->${e.alias}`)
      .sort()
    expect(aliases1).toEqual(aliases2)
  })
})
