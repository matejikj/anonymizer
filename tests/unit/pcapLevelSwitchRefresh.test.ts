/**
 * Regression: switching the PCAP anonymization level must re-derive discovery-dependent
 * disposition (entities, coverage, drop decisions), not just rebuild the plan's patch bytes.
 * `heuristicScan` is on for diagnostic and off for high-privacy, so a payload only findable by
 * the heuristic scanner is a concrete, checkable case: present under diagnostic, gone after
 * switching to high-privacy. Before this fix, `packetDiscovery`/`unifiedCoverage`/`analysis`
 * were never refreshed on a level switch — only the plan's patches were — so this entity (and
 * any 'preserved-unsafe' disposition baked in at the original level) would silently survive
 * the switch, which is what caused the export's unsafe-acknowledgement check to fire
 * incorrectly for an otherwise-clean high-privacy export.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { CaptureFormat, type PacketEnvelope } from '../../src/pcap/domain/types.ts'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter.ts'
import {
  clearPcapSession,
  createSlimPcapSession,
  getPcapSession,
} from '../../src/pcap/ui/pcapSession.ts'
import { usePcapStore } from '../../src/pcap/ui/pcapStore.ts'
import {
  createWorkerPcapPlanRebuildPort,
  getPcapPlanRebuildPort,
  setPcapPlanRebuildPort,
  resetPcapPlanRebuildPort,
} from '../../src/pcap/profile/workerPcapPlanRebuildPort.ts'
import { derivedPolicyView } from '../../src/pcap/profile/presets.ts'
import { setProcessingClientsForTests, resetProcessingClients } from '../../src/pcap/processing/processingOrchestrator.ts'
import { createInProcessPcapProcessingClient } from '../../tests/helpers/inProcessPcapProcessingWorker.ts'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker.ts'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient.ts'
import { runDiscoveryPipeline, identitiesFromDiscovery as identitiesFromSourceDiscovery } from '../../src/pcap/discovery/discoveryPipeline.ts'
import { runCaptureReassembly } from '../../src/pcap/reassembly/capturePhase.ts'
import { profileToSanitizationPolicy } from '../../src/pcap/profile/presets.ts'
import { MappingAuthority } from '../../src/mapping/mappingAuthority.ts'
import { buildDeterministicPlan } from '../../src/pcap/plan/deterministicPlanBuilder.ts'
import { readClassicPcapFromBlob } from '../../src/pcap/capture/pcapReader.ts'
import { buildSessionCoverage } from '../../src/pcap/coverage/index.ts'

function heuristicPacket(index: number): PacketEnvelope {
  // Ethernet + IPv4 + UDP on an unrecognized port, ASCII payload embedding a dotted IPv4 —
  // only the heuristic scanner (diagnostic-only) finds this; DNS/DHCP/SIP/TLS/HTTP won't.
  const text = 'peer=203.0.113.9 status=ok'
  const payload = new TextEncoder().encode(text)
  const data = new Uint8Array(14 + 20 + 8 + payload.length)
  data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  const ipTotalLen = 20 + 8 + payload.length
  data[16] = (ipTotalLen >> 8) & 0xff
  data[17] = ipTotalLen & 0xff
  data[23] = 17 // UDP
  data.set([10, 0, 0, 1], 26)
  data.set([10, 0, 0, 2], 30)
  const udpStart = 34
  data[udpStart] = 0x30 // src port 12345 (unrecognized)
  data[udpStart + 1] = 0x39
  data[udpStart + 2] = 0x30
  data[udpStart + 3] = 0x3a // dst port 12346
  const udpTotalLen = 8 + payload.length
  data[udpStart + 4] = (udpTotalLen >> 8) & 0xff
  data[udpStart + 5] = udpTotalLen & 0xff
  data.set(payload, udpStart + 8)
  return {
    packetNumber: index,
    timestamp: { ticks: BigInt(index), unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

async function buildDiagnosticSession(fileName: string) {
  const packets = [heuristicPacket(0)]
  const profile = derivedPolicyView('diagnostic')
  const policy = profileToSanitizationPolicy(profile)
  const buffer = writeClassicPcap({
    header: {
      format: CaptureFormat.ClassicPcap,
      endian: 0,
      timestampResolution: 0,
      versionMajor: 2,
      versionMinor: 4,
      snapLen: 65535,
      linkType: 1,
      tzOffset: 0,
      sigfigs: 0,
    },
    packets,
  })
  const blob = new Blob([buffer])
  const file = new File([blob], fileName, { type: 'application/octet-stream' })
  const read = await readClassicPcapFromBlob(blob)
  const reassembly = runCaptureReassembly(read.packets, policy)
  const discovery = runDiscoveryPipeline(read.packets, policy, 'test-gen', fileName, {
    reassemblyContext: reassembly,
  })
  const authority = new MappingAuthority({
    ip: profile.mapping.ip,
    mac: profile.mapping.mac,
    timestamps: profile.mapping.timestamps,
    ephemeralPorts: profile.mapping.ephemeralPorts,
      contentSignalingPorts: profile.mapping.contentSignalingPorts,
    vlan: profile.mapping.vlan,
  })
  const identities = identitiesFromSourceDiscovery(discovery)
  const resolved = authority.resolve({ generationId: 'test-gen', sourceId: fileName, identities })
  if (!resolved.ok) throw new Error(resolved.message)
  const plan = buildDeterministicPlan({
    generationId: 'test-gen',
    profile,
    format: CaptureFormat.ClassicPcap,
    fileName,
    packets: read.packets,
    policy,
    snapshot: resolved.snapshot,
    reassemblyContext: reassembly,
    classicHeader: read.header ?? undefined,
    packetDiscovery: discovery.packetDiscovery,
  })
  const { unifiedCoverage, entityOccurrenceIndex } = buildSessionCoverage({
    packetCount: read.descriptors.length,
    analysis: discovery.analysis,
    packetDiscovery: discovery.packetDiscovery,
  })
  createSlimPcapSession({
    descriptor: {
      fileName,
      fileSize: buffer.byteLength,
      format: CaptureFormat.ClassicPcap,
      sourceFile: file,
      descriptors: [...read.descriptors],
      checkpoints: [...read.checkpoints],
      issues: [...read.issues],
      classicHeader: read.header ?? undefined,
    },
    generationId: 'test-gen',
    analysis: discovery.analysis,
    packetDiscovery: discovery.packetDiscovery,
    unifiedCoverage,
    entityOccurrenceIndex,
    plan,
    mappingRevision: resolved.snapshot.revision,
    profile,
  })
}

describe('PF-19: PCAP level switch refreshes discovery-derived disposition', () => {
  beforeEach(() => {
    clearPcapSession()
    usePcapStore.getState().resetToEmpty()
    setProcessingClientsForTests(
      createInProcessPcapProcessingClient(),
      new MappingWorkerClient(createInProcessMappingWorkerFactory()),
    )
    setPcapPlanRebuildPort(createWorkerPcapPlanRebuildPort())
  })

  afterEach(() => {
    resetProcessingClients()
    resetPcapPlanRebuildPort()
  })

  it('re-derives payload disposition after switching to high-privacy (T74/PF-19)', async () => {
    await buildDiagnosticSession('heuristic-switch.pcap')

    const before = getPcapSession()!
    expect(before.policy.preset).toBe('diagnostic')
    // Diagnostic claims unrecognized payload via T74 proprietary-light and/or heuristic.
    const beforeCov = before.packetDiscovery[0]!.coverage
    const diagClaim = beforeCov.find(
      (c) =>
        c.protocol === 'heuristic'
        || c.protocol === 'proprietary-light'
        || c.protocol.startsWith('proprietary-light'),
    )
    expect(diagClaim).toBeTruthy()

    const result = await getPcapPlanRebuildPort().rebuildPlan('high-privacy')
    expect(result.applied).toBe(true)

    const after = getPcapSession()!
    expect(after.policy.preset).toBe('high-privacy')
    // The session objects must actually be replaced, not the stale pre-switch ones reused.
    expect(after.analysis).not.toBe(before.analysis)
    expect(after.unifiedCoverage).not.toBe(before.unifiedCoverage)
    expect(after.packetDiscovery).not.toBe(before.packetDiscovery)
    // High-privacy turns off light/heuristic claim → unsupported/truncated rollup.
    expect(after.packetDiscovery).toEqual([])
    expect(after.coverageRollup).toBeDefined()
    expect(after.coverageRollup!.totalHeuristicSpans).toBe(0)
    expect(after.coverageRollup!.totalUnsupportedSpans).toBeGreaterThan(0)
    expect(after.unifiedCoverage.totalUnsupportedSpans).toBeGreaterThan(0)
    expect(after.statuses.heuristicCount).toBe(0)
  })

  it('keeps worker coverage rollup in statuses across a same-policy plan rebuild', async () => {
    await buildDiagnosticSession('rollup-keep.pcap')
    await getPcapPlanRebuildPort().rebuildPlan('high-privacy')
    const switched = getPcapSession()!
    const rollup = switched.coverageRollup!
    expect(rollup.totalUnsupportedSpans).toBeGreaterThan(0)

    // Same level again → fast plan-only rebuild; statuses must still reflect the rollup.
    const again = await getPcapPlanRebuildPort().rebuildPlan('high-privacy')
    expect(again.applied).toBe(true)
    const after = getPcapSession()!
    expect(after.coverageRollup).toBe(rollup)
    expect(after.statuses.unsupportedCount).toBe(switched.statuses.unsupportedCount)
    expect(after.statuses.issueCount).toBe(switched.statuses.issueCount)
  })
})
