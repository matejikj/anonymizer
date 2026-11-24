import { describe, expect, it, beforeEach } from 'vitest'
import {
  clearPcapSession,
  filterPacketIndices,
  getPcapSession,
  DEFAULT_PCAP_FILTER,
  computeStatusesFromDiscovery,
  findPacketIndexByNumber,
} from '../../../src/pcap/ui/pcapSession'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { createPresetProfile, profileToSanitizationPolicy } from '../../../src/pcap/profile/presets'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'
import { refreshPcapFilter } from '../../../src/pcap/ui/pcapLoadController'
import { createTestPcapSessionFromPackets } from './pcapSessionTestHelpers'
import { buildUnifiedCoverageModel } from '../../../src/pcap/coverage'
import { emptyAnalysis } from '../../../src/pcap/ui/pcapSession'

function makeEthIpPacket(src: number[], dst: number[], packetNumber: number): PacketEnvelope {
  const data = new Uint8Array(42)
  data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  data[16] = 0
  data[17] = 28
  data[23] = 17
  data.set(src, 26)
  data.set(dst, 30)
  return {
    packetNumber,
    timestamp: { ticks: BigInt(packetNumber) * 1000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

describe('pcapSession (Stage 9 slim)', () => {
  beforeEach(() => {
    clearPcapSession()
  })

  it('creates slim session with plan and statuses', async () => {
    const packets = [
      makeEthIpPacket([192, 168, 1, 10], [10, 0, 0, 1], 1),
      makeEthIpPacket([192, 168, 1, 11], [10, 0, 0, 2], 2),
    ]
    const session = await createTestPcapSessionFromPackets({
      fileName: 'test.pcap',
      packets,
    })

    expect(session.descriptors.length).toBe(2)
    expect(session.plan.packets.length).toBe(2)
    expect(session.statuses.changedCount).toBeGreaterThan(0)
    expect(session.statuses.anonymization).toBe('covered')
    expect(session.statuses.compatibility).toBe('valid')
    expect(getPcapSession()?.plan).toBe(session.plan)
  })

  it('marks diagnostic level as covered for standard IP traffic', async () => {
    const profile = createPresetProfile('diagnostic')
    const packets = [makeEthIpPacket([192, 168, 1, 10], [8, 8, 8, 8], 1)]
    const session = await createTestPcapSessionFromPackets({
      fileName: 'a.pcap',
      packets,
      profile,
    })
    expect(session.statuses.anonymization).toBe('covered')
  })

  it('filters changed-only packets', async () => {
    const packets = [
      makeEthIpPacket([192, 168, 1, 10], [10, 0, 0, 1], 1),
      makeEthIpPacket([192, 168, 1, 11], [10, 0, 0, 2], 2),
    ]
    await createTestPcapSessionFromPackets({ fileName: 'f.pcap', packets })

    const all = filterPacketIndices(DEFAULT_PCAP_FILTER)
    expect(all.length).toBe(2)

    const changed = filterPacketIndices({ ...DEFAULT_PCAP_FILTER, changedOnly: true })
    expect(changed.length).toBeGreaterThan(0)

    const ranged = filterPacketIndices({ ...DEFAULT_PCAP_FILTER, packetFrom: 1, packetTo: 1 })
    expect(ranged.length).toBe(1)
    expect(getPcapSession()?.descriptors[ranged[0]!]?.packetNumber).toBe(1)
  })

  it('findPacketIndexByNumber resolves descriptor index', async () => {
    const packets = [makeEthIpPacket([10, 0, 0, 1], [10, 0, 0, 2], 0)]
    await createTestPcapSessionFromPackets({ fileName: 'n.pcap', packets })
    expect(findPacketIndexByNumber(0)).toBe(0)
  })

  it('filters by display expression', async () => {
    const packets = [
      makeEthIpPacket([192, 168, 1, 10], [10, 0, 0, 1], 1),
      makeEthIpPacket([192, 168, 1, 11], [10, 0, 0, 2], 2),
    ]
    await createTestPcapSessionFromPackets({ fileName: 'df.pcap', packets })

    const byNum = filterPacketIndices(DEFAULT_PCAP_FILTER, 'frame.number == 1')
    expect(byNum.length).toBe(1)
    expect(getPcapSession()?.descriptors[byNum[0]!]?.packetNumber).toBe(1)
  })

  it('filters sip protocol from sanitizer coverage', async () => {
    const { buildEthIpUdp, buildSipInviteWithSdp, envelope } = await import('../fixtures/voipCorpus')
    const sipPayload = buildSipInviteWithSdp({ transport: 'udp' })
    const data = buildEthIpUdp([192, 168, 55, 10], [192, 168, 55, 20], 5060, 5060, sipPayload)
    await createTestPcapSessionFromPackets({
      fileName: 'sip-filter.pcap',
      packets: [envelope(data, 1)],
    })
    const sipOnly = filterPacketIndices(DEFAULT_PCAP_FILTER, 'sip')
    expect(sipOnly.length).toBe(1)
    const udpOnly = filterPacketIndices(DEFAULT_PCAP_FILTER, 'udp')
    expect(udpOnly.length).toBe(1)
  })

  it('refreshPcapFilter updates store indices', async () => {
    const packets = [
      makeEthIpPacket([192, 168, 1, 10], [10, 0, 0, 1], 1),
      makeEthIpPacket([192, 168, 1, 11], [10, 0, 0, 2], 2),
    ]
    await createTestPcapSessionFromPackets({ fileName: 'r.pcap', packets })
    usePcapStore.getState().setFilter({ ...DEFAULT_PCAP_FILTER, changedOnly: true })
    refreshPcapFilter()
    expect(usePcapStore.getState().filteredIndices.length).toBeGreaterThan(0)
  })

  it('computeStatusesFromDiscovery blocks on entity overflow', () => {
    const analysis = { ...emptyAnalysis(), entityOverflow: true }
    const unifiedCoverage = buildUnifiedCoverageModel({
      packetCount: 0,
      analysis,
      packetDiscovery: [],
    })
    const statuses = computeStatusesFromDiscovery({
      issues: [],
      analysis,
      unifiedCoverage,
      plan: {
        generationId: 'g',
        profileId: 'p',
        profileHash: 'h',
        format: CaptureFormat.ClassicPcap,
        fileName: 'x.pcap',
        engineVersion: '1',
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
      },
      policy: profileToSanitizationPolicy(createPresetProfile('diagnostic')),
    })
    expect(statuses.anonymization).toBe('blocked')
  })
})
