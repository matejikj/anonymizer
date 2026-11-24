import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { PassthroughMapping } from '../../src/pcap/discovery/passthroughMapping.ts'
import { discoverPacket } from '../../src/pcap/discovery/discoverPacket.ts'
import { runDiscoveryPipeline } from '../../src/pcap/discovery/discoveryPipeline.ts'
import { policyFromPreset } from '../../src/pcap/sanitize/engine.ts'
import type { PacketEnvelope } from '../../src/pcap/domain/types.ts'

function makeEthIpv4Packet(i: number): PacketEnvelope {
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
    packetNumber: i,
    timestamp: { ticks: BigInt(i), unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 24 + i * 40,
    data,
  }
}

describe('PCAP discovery (Stage 8)', () => {
  it('PassthroughMapping never changes canonical values', () => {
    const p = new PassthroughMapping()
    expect(p.map('ipv4', '10.0.0.1')).toBe('10.0.0.1')
    expect(p.map('mac', 'aa:bb:cc:dd:ee:ff')).toBe('aa:bb:cc:dd:ee:ff')
  })

  it('discoverPacket records entity-replacement intents without pseudonyms', () => {
    const pkt = makeEthIpv4Packet(0)
    const policy = policyFromPreset('high-privacy')
    const discovered = discoverPacket({
      index: 0,
      data: pkt.data,
      capturedLength: pkt.capturedLength,
      originalLength: pkt.originalLength,
      linkType: 1,
    }, 0, policy)

    expect(discovered.intents.some((i) => i.kind === 'entity-replacement')).toBe(true)
    for (const intent of discovered.intents) {
      if (intent.kind !== 'entity-replacement') continue
      expect(intent.canonical).not.toMatch(/^10\.254\./)
    }
  })

  it('runDiscoveryPipeline aggregates intents in batches', () => {
    const packets = Array.from({ length: 5 }, (_, i) => makeEthIpv4Packet(i))
    const discovery = runDiscoveryPipeline(packets, policyFromPreset('high-privacy'), 'gen', 'src', {
      batchSize: 2,
    })
    expect(discovery.totalPackets).toBe(5)
    expect(discovery.intents.length).toBeGreaterThan(0)
  })
})
