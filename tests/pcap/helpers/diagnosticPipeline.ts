/**
 * Shared diagnostic export pipeline for step 10 release gates.
 */

import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import type { ClassicPcapHeader, PacketEnvelope } from '../../../src/pcap/domain/types'
import {
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  createPresetProfile,
  type PcapAnonymizationLevel,
} from '../../../src/pcap/profile/presets'
import { runDiscoveryPipeline, identitiesFromDiscovery } from '../../../src/pcap/discovery/discoveryPipeline'
import { runCaptureReassembly } from '../../../src/pcap/reassembly/capturePhase'
import { MappingAuthority } from '../../../src/mapping/mappingAuthority'
import { buildDeterministicPlan } from '../../../src/pcap/plan/deterministicPlanBuilder'
import {
  dedupeIdentities,
  identitiesForClosureFailures,
  validateMappingClosure,
} from '../../../src/pcap/plan/mappingClosureValidation'
import { buildCaptureFromPlan, buildSafeReport } from '../../../src/pcap/export/engine'
import { buildAiDiagnosticsManifest } from '../../../src/pcap/export/aiDiagnostics'
import type { PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import type { MappingSnapshot } from '../../../src/mapping/types'

export function classicHeader(linkType = 1): ClassicPcapHeader {
  return {
    format: CaptureFormat.ClassicPcap,
    endian: Endian.Little,
    timestampResolution: TimestampResolution.Microseconds,
    versionMajor: 2,
    versionMinor: 4,
    snapLen: 65535,
    linkType,
    tzOffset: 0,
    sigfigs: 0,
  }
}

export interface DiagnosticPipelineResult {
  readonly discovery: ReturnType<typeof runDiscoveryPipeline>
  readonly plan: PcapPlanSnapshot
  readonly snapshot: MappingSnapshot
  readonly packets: readonly PacketEnvelope[]
  readonly built: ReturnType<typeof buildCaptureFromPlan>
  readonly reportJson: string
  readonly aiDiagnosticsJson: string
}

export function runDiagnosticExportPipeline(
  packets: readonly PacketEnvelope[],
  fileName = 'diagnostic-gate.pcap',
  generationId = 'diagnostic-gate',
  options?: { readonly mappingSeed?: string; readonly verifyLeaks?: boolean; readonly onStage?: (stage: string) => void },
): DiagnosticPipelineResult {
  return runExportPipeline(packets, 'diagnostic', fileName, generationId, options)
}

/** Step 7 — same pipeline, parameterized by level, so both fixed levels can be built from the
 * exact same original packets in one test run (see dtPcapRegressionGate.test.ts). */
export function runExportPipeline(
  packets: readonly PacketEnvelope[],
  level: PcapAnonymizationLevel,
  fileName = 'export-gate.pcap',
  generationId = 'export-gate',
  options?: { readonly mappingSeed?: string; readonly verifyLeaks?: boolean; readonly onStage?: (stage: string) => void },
): DiagnosticPipelineResult {
  const policy = level === 'diagnostic' ? DIAGNOSTIC_POLICY : HIGH_PRIVACY_POLICY
  const profile = createPresetProfile(level, { id: generationId, name: `${level} gate` })
  const reassembly = runCaptureReassembly(packets, policy)
  options?.onStage?.('reassembly')
  const discovery = runDiscoveryPipeline(packets, policy, generationId, fileName, {
    reassemblyContext: reassembly,
  })
  const authority = new MappingAuthority(
    {
      ip: profile.mapping.ip,
      mac: profile.mapping.mac,
      timestamps: profile.mapping.timestamps,
      ephemeralPorts: profile.mapping.ephemeralPorts,
      contentSignalingPorts: profile.mapping.contentSignalingPorts,
      vlan: profile.mapping.vlan,
    },
    options?.mappingSeed ? { seed: options.mappingSeed } : undefined,
  )
  options?.onStage?.('discovery')
  const identities = identitiesFromDiscovery(discovery)
  let resolved = authority.resolve({ generationId, sourceId: fileName, identities })
  if (!resolved.ok) throw new Error(`mapping resolve failed: ${resolved.message}`)
  let unresolvedFailures: import('../../../src/pcap/plan/mappingClosureValidation').MappingClosureFailure[] = []
  let closure = validateMappingClosure(discovery.intents, resolved.snapshot)
  if (!closure.ok) {
    const topUp = identitiesForClosureFailures(closure.failures)
    resolved = authority.resolve({
      generationId,
      sourceId: fileName,
      identities: dedupeIdentities([...identities, ...topUp]),
    })
    if (!resolved.ok) throw new Error(`mapping resolve failed: ${resolved.message}`)
    closure = validateMappingClosure(discovery.intents, resolved.snapshot)
    // T04: soft-fail — field fallback + incidents instead of aborting the export.
    if (!closure.ok) unresolvedFailures = [...closure.failures]
  }

  const leakOriginals = options?.verifyLeaks ? discovery.analysis.entities.map((entity) => ({
    category: entity.category,
    value: entity.value,
    packetNumber: 0,
  })) : undefined
  options?.onStage?.('mapping')
  const plan = buildDeterministicPlan({
    generationId,
    profile,
    format: CaptureFormat.ClassicPcap,
    fileName,
    packets,
    policy,
    snapshot: resolved.snapshot,
    reassemblyContext: reassembly,
    classicHeader: classicHeader(packets[0]?.linkType ?? 1),
    // Reuse discovery's own per-packet decisions (coverage/intents/MediaFlowIndex
    // classification) instead of re-running sanitizePacket() a second time — the shared,
    // stateful MediaFlowIndex conversation evidence must not be built up twice against the
    // same packets, or plan-build would see more accumulated evidence than discovery did
    // and disagree with it on which SSRCs/entities need a mapping alias.
    packetDiscovery: discovery.packetDiscovery,
    sourceId: fileName,
    unresolvedClosureFailures: unresolvedFailures,
    leakOriginals,
  })
  options?.onStage?.('plan')
  const built = buildCaptureFromPlan(plan, packets)
  options?.onStage?.('capture')
  const validation = {
    valid: built.validationValid,
    exportValidation: {
      valid: built.validationValid,
      packetCount: built.packets.length,
      issues: [],
    },
    exportIssues: [],
    newBlockingIssues: [],
    preservedBaselineIssues: [],
    validationValid: built.validationValid,
    validationIssueCount: built.validationIssueCount,
  }
  const report = buildSafeReport(
    plan,
    {
      fileName: built.fileName,
      changedPackets: built.changedPackets,
      truncatedPayloads: built.truncatedPayloads,
      checksumReport: built.checksumReport,
      validation,
      leakOriginals,
      anonymizedBytes: options?.verifyLeaks ? new Uint8Array(built.buffer) : undefined,
    },
    0,
    discovery.unifiedCoverage.byProtocol,
    {
      plan,
      profile,
      policy,
      coverage: discovery.packetDiscovery.flatMap((p) => p.coverage),
      // high-privacy's tcpOptions: 'preserve-unsafe' (see pcapAnonymizationLevel.ts) means any
      // TCP-bearing capture legitimately requires unsafe-export confirmation — this helper
      // exercises pipeline/privacy correctness, not the UI confirmation dialog, so acknowledge
      // it unconditionally here rather than have every high-privacy caller need to know that.
      unsafeExportAcknowledged: true,
    },
  )
  const reportJson = JSON.stringify(report)
  options?.onStage?.('report')
  const aiManifest = buildAiDiagnosticsManifest({
    plan,
    protocolCoverage: discovery.unifiedCoverage.byProtocol,
  })
  const aiDiagnosticsJson = JSON.stringify(aiManifest)
  return {
    discovery,
    plan,
    snapshot: resolved.snapshot,
    packets,
    built,
    reportJson,
    aiDiagnosticsJson,
  }
}

export function countCoverageProtocol(
  discovery: ReturnType<typeof runDiscoveryPipeline>,
  protocol: string,
): number {
  const row = discovery.unifiedCoverage.byProtocol.find((p) => p.protocol === protocol)
  return row?.packetCount ?? 0
}
