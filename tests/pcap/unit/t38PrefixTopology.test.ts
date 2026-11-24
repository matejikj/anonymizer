/**
 * T38.prefix — topology-preserving IPv4 keeps /24 and prefix↔host coherence after collisions.
 */
import { describe, expect, it } from 'vitest'
import { DEFAULT_MAPPING_CONFIG } from '../../../src/pcap/anonymization/mapping'
import { createTestSessionMapping } from '../../../src/pcap/anonymization/testModeSeed'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { mapIpv4Prefix } from '../../../src/pcap/sanitize/routing/common'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'

function thirdOctet(ip: string): string {
  return ip.split('.')[2]!
}

function envelope(data: Uint8Array): PacketEnvelope {
  return {
    packetNumber: 1,
    timestamp: { ticks: 1n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

describe('T38.prefix mapping', () => {
  it('keeps same /24 third octet when topology first candidate collides', () => {
    const mapping = createTestSessionMapping('t48-topo-collide-seed-eeeeeeee', {
      ...DEFAULT_MAPPING_CONFIG,
      ip: 'topology-preserving',
    })
    const a = mapping.map('ipv4', '10.1.2.3')
    const b = mapping.map('ipv4', '10.1.2.4')
    expect(a).not.toBe(b)
    expect(thirdOctet(a)).toBe(thirdOctet(b))
    expect(a.startsWith('10.254.')).toBe(true)
  })

  it('mapIpv4Prefix aligns network address with hosts in the same /24', () => {
    const mapping = createTestSessionMapping('t38-prefix-wire', {
      ...DEFAULT_MAPPING_CONFIG,
      ip: 'topology-preserving',
    })
    const hostAlias = mapping.map('ipv4', '10.20.30.8')
    const buf = new Uint8Array([10, 20, 30, 200])
    const collector = new PatchCollector()
    mapIpv4Prefix(buf, 0, 24, collector, mapping, undefined, 0, 'rip')
    collector.resolveDeferred({ mapping })
    for (const p of collector.getPatches()) buf.set(p.data, p.offset)
    const wired = `${buf[0]}.${buf[1]}.${buf[2]}.${buf[3]}`
    expect(thirdOctet(wired)).toBe(thirdOctet(hostAlias))
    expect(buf[3]).toBe(0)
  })

  it('export pipeline keeps RIP route and src IP in the same mapped /24', () => {
    const payload = new Uint8Array(4 + 20)
    payload[0] = 2
    payload[1] = 2
    payload[4] = 0
    payload[5] = 2 // AFI IPv4
    payload.set([10, 20, 30, 0], 8) // network
    payload.set([255, 255, 255, 0], 12) // mask
    payload.set([10, 20, 30, 1], 16) // next-hop
    const frame = buildEthIpUdp([10, 20, 30, 5], [192, 0, 2, 2], 520, 520, payload)
    const exported = runExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't38-prefix-export.pcap',
      't38-prefix-export',
      { mappingSeed: 't38-prefix-export-seed' },
    )
    const out = exported.built.packets[0]!.data
    const srcOff = 26
    const routeNetOff = 14 + 20 + 8 + 8
    const nextHopOff = routeNetOff + 8
    const src = `${out[srcOff]}.${out[srcOff + 1]}.${out[srcOff + 2]}.${out[srcOff + 3]}`
    const net = `${out[routeNetOff]}.${out[routeNetOff + 1]}.${out[routeNetOff + 2]}.${out[routeNetOff + 3]}`
    const nh = `${out[nextHopOff]}.${out[nextHopOff + 1]}.${out[nextHopOff + 2]}.${out[nextHopOff + 3]}`
    expect(src).toMatch(/^10\.254\./)
    expect(thirdOctet(src)).toBe(thirdOctet(net))
    expect(thirdOctet(src)).toBe(thirdOctet(nh))
    expect(src.startsWith('10.20.30.')).toBe(false)
    expect(net.startsWith('10.20.30.')).toBe(false)
  })
})
