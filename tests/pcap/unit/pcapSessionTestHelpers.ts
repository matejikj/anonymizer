/**
 * Test helpers for slim PCAP session (Stage 9).
 */

import { CaptureFormat, type PacketEnvelope, type ParseIssue } from '../../../src/pcap/domain/types'
import type { PcapProfile } from '../../../src/pcap/profile/schema'
import { createDefaultPcapProfile, profileToSanitizationPolicy } from '../../../src/pcap/profile/presets'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import { runDiscoveryPipeline, identitiesFromDiscovery } from '../../../src/pcap/discovery/discoveryPipeline'
import { runCaptureReassembly } from '../../../src/pcap/reassembly/capturePhase'
import type { ReassemblyContext } from '../../../src/pcap/reassembly/types'
import { MappingAuthority } from '../../../src/mapping/mappingAuthority'
import { buildDeterministicPlan } from '../../../src/pcap/plan/deterministicPlanBuilder'
import {
  dedupeIdentities,
  identitiesForClosureFailures,
  validateMappingClosure,
} from '../../../src/pcap/plan/mappingClosureValidation'
import { createSlimPcapSession, type PcapSession } from '../../../src/pcap/ui/pcapSession'
import type { PcapSourceDescriptor } from '../../../src/pcap/ui/pcapSourceDescriptor'
import { readClassicPcapFromBlob } from '../../../src/pcap/capture/pcapReader'
import type { SanitizationPolicy } from '../../../src/pcap/sanitize/types'
import type { CanonicalIdentity, MappingSnapshot } from '../../../src/mapping/types'
import type { TransformationIntent } from '../../../src/pcap/discovery/types'

function resolveWithClosureSync(input: {
  generationId: string
  sourceId: string
  identities: readonly CanonicalIdentity[]
  intents: readonly TransformationIntent[]
  authority: MappingAuthority
  packetNumberForIndex?: (packetIndex: number) => number | undefined
}): MappingSnapshot {
  const resolveOnce = (ids: readonly CanonicalIdentity[]): MappingSnapshot => {
    const resolved = input.authority.resolve({
      generationId: input.generationId,
      sourceId: input.sourceId,
      identities: ids,
    })
    if (!resolved.ok) throw new Error(resolved.message)
    return resolved.snapshot
  }

  let snapshot = resolveOnce(input.identities)
  let validation = validateMappingClosure(input.intents, snapshot)
  if (validation.ok) return snapshot

  const topUp = identitiesForClosureFailures(validation.failures)
  snapshot = resolveOnce(dedupeIdentities([...input.identities, ...topUp]))
  // T04: remaining closure failures soft-fail — plan build field-masks + incidents.
  void input.packetNumberForIndex
  void validateMappingClosure(input.intents, snapshot)
  return snapshot
}

export function resolveSnapshotForPackets(
  packets: readonly PacketEnvelope[],
  policy: SanitizationPolicy,
  generationId = 'test-gen',
  sourceId = 'test.pcap',
  reassemblyContext?: ReassemblyContext,
): MappingSnapshot {
  const profile = createDefaultPcapProfile().profile
  const discovery = runDiscoveryPipeline(packets, policy, generationId, sourceId, {
    reassemblyContext,
  })
  const authority = new MappingAuthority({
    ip: profile.mapping.ip,
    mac: profile.mapping.mac,
    timestamps: profile.mapping.timestamps,
    ephemeralPorts: profile.mapping.ephemeralPorts,
      contentSignalingPorts: profile.mapping.contentSignalingPorts,
    vlan: profile.mapping.vlan,
  })
  return resolveWithClosureSync({
    generationId,
    sourceId,
    identities: identitiesFromDiscovery(discovery),
    intents: discovery.intents,
    authority,
    packetNumberForIndex: (idx) => packets[idx]?.packetNumber,
  })
}

export async function createTestPcapSessionFromPackets(init: {
  fileName: string
  packets: PacketEnvelope[]
  issues?: ParseIssue[]
  profile?: PcapProfile
}): Promise<PcapSession> {
  const profile = init.profile ?? createDefaultPcapProfile().profile
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
    packets: init.packets,
  })
  const blob = new Blob([buffer])
  const file = new File([blob], init.fileName, { type: 'application/octet-stream' })
  const read = await readClassicPcapFromBlob(blob)

  const reassembly = runCaptureReassembly(read.packets, policy)
  const discovery = runDiscoveryPipeline(read.packets, policy, 'test-gen', init.fileName, {
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

  const snapshot = resolveWithClosureSync({
    generationId: 'test-gen',
    sourceId: init.fileName,
    identities: identitiesFromDiscovery(discovery),
    intents: discovery.intents,
    authority,
    packetNumberForIndex: (idx) => read.packets[idx]?.packetNumber,
  })

  const plan = buildDeterministicPlan({
    generationId: 'test-gen',
    profile,
    format: CaptureFormat.ClassicPcap,
    fileName: init.fileName,
    packets: read.packets,
    policy,
    snapshot,
    classicHeader: read.header ?? undefined,
    reassemblyContext: reassembly,
  })

  const descriptor: PcapSourceDescriptor = {
    fileName: init.fileName,
    fileSize: buffer.byteLength,
    format: CaptureFormat.ClassicPcap,
    sourceFile: file,
    descriptors: [...read.descriptors],
    checkpoints: [...read.checkpoints],
    issues: init.issues ?? [...read.issues],
    classicHeader: read.header ?? undefined,
  }

  return createSlimPcapSession({
    descriptor,
    generationId: 'test-gen',
    analysis: discovery.analysis,
    packetDiscovery: discovery.packetDiscovery,
    unifiedCoverage: discovery.unifiedCoverage,
    entityOccurrenceIndex: discovery.entityOccurrenceIndex,
    plan,
    mappingRevision: snapshot.revision,
    profile,
  })
}
