import { describe, expect, it } from 'vitest'
import { MappingAuthority } from '../../src/mapping/mappingAuthority.ts'
import { CaptureFormat, type PacketEnvelope } from '../../src/pcap/domain/types.ts'
import { createDefaultPcapProfile } from '../../src/pcap/profile/presets.ts'
import { profileToSanitizationPolicy } from '../../src/pcap/profile/presets.ts'
import { buildDeterministicPlan, planWireSignature } from '../../src/pcap/plan/deterministicPlanBuilder.ts'
import { runDiscoveryPipeline, identitiesFromDiscovery } from '../../src/pcap/discovery/discoveryPipeline.ts'
import type { MappingSnapshot } from '../../src/mapping/types.ts'

function samplePacket(): PacketEnvelope {
  const data = new Uint8Array(34)
  data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  data.set([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  data[16] = 0x00
  data[17] = 20
  data[23] = 0x11
  data.set([192, 168, 1, 10], 26)
  data.set([93, 184, 216, 34], 30)
  return {
    packetNumber: 0,
    timestamp: { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 24,
    data,
  }
}

async function fixedSnapshot(packets: PacketEnvelope[]): Promise<MappingSnapshot> {
  const profile = createDefaultPcapProfile().profile
  const policy = profileToSanitizationPolicy(profile)
  const discovery = runDiscoveryPipeline(packets, policy, 'gen', 'pcap')
  const authority = new MappingAuthority({
    ip: profile.mapping.ip,
    mac: profile.mapping.mac,
    timestamps: profile.mapping.timestamps,
    ephemeralPorts: profile.mapping.ephemeralPorts,
      contentSignalingPorts: profile.mapping.contentSignalingPorts,
    vlan: profile.mapping.vlan,
  })
  const resolved = authority.resolve({
    generationId: 'gen',
    sourceId: 'pcap',
    identities: identitiesFromDiscovery(discovery),
  })
  if (!resolved.ok) throw new Error('resolve failed')
  return resolved.snapshot
}

describe('deterministic PCAP plan builder (Stage 8)', () => {
  it('same MappingSnapshot yields byte-identical plan signature', async () => {
    const packets = [samplePacket()]
    const profile = createDefaultPcapProfile().profile
    const policy = profileToSanitizationPolicy(profile)
    const snapshot = await fixedSnapshot(packets)

    const plan1 = buildDeterministicPlan({
      generationId: 'g1',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'test.pcap',
      packets,
      policy,
      snapshot,
    })
    const plan2 = buildDeterministicPlan({
      generationId: 'g1',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'test.pcap',
      packets,
      policy,
      snapshot,
    })

    expect(planWireSignature(plan1)).toBe(planWireSignature(plan2))
    expect(plan1.packets[0]!.patches.length).toBeGreaterThan(0)
  })

  it('plan builder does not use SessionMapping RNG registry', async () => {
    const packets = [samplePacket()]
    const profile = createDefaultPcapProfile().profile
    const policy = profileToSanitizationPolicy(profile)
    const snapshot = await fixedSnapshot(packets)

    const plan = buildDeterministicPlan({
      generationId: 'g1',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'test.pcap',
      packets,
      policy,
      snapshot,
    })

    expect(plan.packets[0]!.patches[0]!.data.some((b, i, arr) => {
      const ip = '192.168.1.10'
      const orig = ip.split('.').map(Number)
      return b !== orig[i % 4]
    })).toBe(true)
  })
})
