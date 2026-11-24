/**
 * R10 — packed discover wire must round-trip and stay far below the nested-object graph size.
 */
import { describe, expect, it } from 'vitest'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import {
  containerMetadataFromSession,
  containerMetadataFromSessionTransferable,
  discoveryToWire,
  processCapture,
} from '../../../src/pcap/processing/processingPipeline'
import { containerFromWire } from '../../../src/pcap/processing/containerWireAdapter'
import { packDescriptors, unpackDescriptors } from '../../../src/pcap/processing/packedCaptureWire'
import { sourceDiscoveryFromWire } from '../../../src/pcap/processing/discoveryWireAdapter'
import { buildSessionCoverage } from '../../../src/pcap/coverage/sessionCoverage'
import { coverageRowsFromProtocolSummaries, buildAnonymizationOutcome } from '../../../src/pcap/coverage/anonymizationOutcome'
import { buildEthIpUdp, buildSipInviteWithSdp, envelope } from '../fixtures/voipCorpus'
import { analyzePackets } from '../../../src/pcap/protocols/analysis'
import { profileToSanitizationPolicy, createPresetProfile } from '../../../src/pcap/profile/presets'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { packetHasProtocol } from '../../../src/pcap/coverage/buildUnifiedCoverage'

function ethPacket(index: number): PacketEnvelope {
  const data = new Uint8Array(64)
  data.set([0x00, 0x11, 0x22, 0x33, 0x44, index & 0xff], 0)
  data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  data[16] = 0
  data[17] = 50
  data[23] = 17
  data.set([10, 0, 0, (index % 200) + 1], 26)
  data.set([10, 0, 1, 1], 30)
  return {
    packetNumber: index,
    timestamp: {
      ticks: BigInt(index) * 1_000_000n,
      unitsPerSecond: 1_000_000n,
      offsetSeconds: 0n,
    },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

describe('packedCaptureWire (R10)', () => {
  it('counts a protocol once per packet when the same layer is nested in a tunnel', () => {
    const inner = buildEthIpUdp([10, 1, 0, 1], [10, 1, 0, 2], 5060, 5060, buildSipInviteWithSdp()).subarray(14)
    const outer = new Uint8Array(14 + 40 + inner.length)
    outer.set([0x08, 0x00], 12)
    outer[14] = 0x45
    new DataView(outer.buffer).setUint16(16, 40 + inner.length)
    outer[23] = 4
    outer.set([10, 0, 0, 1, 10, 0, 0, 2], 26)
    outer[34] = 0x45
    new DataView(outer.buffer).setUint16(36, 20 + inner.length)
    outer[43] = 4
    outer.set([10, 2, 0, 1, 10, 2, 0, 2], 46)
    outer.set(inner, 54)
    const analysis = analyzePackets([envelope(outer, 0)])
    expect(analysis.summaries[0]!.protocols.filter(p => p === 'ipip-ipv4')).toHaveLength(2)
    // Analysis histogram counts decoded nodes; coverage packetCount counts distinct packets.
    expect(analysis.histogram.counts.get('ipip-ipv4')).toBe(2)
    expect(analysis.coverage.find(p => p.protocolId === 'ipip-ipv4')?.packetCount).toBe(1)
  })
  it('keeps actual protocol and unique family counts across the worker boundary', async () => {
    const packets = [0, 1].map(i => envelope(buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, buildSipInviteWithSdp()), i))
    const buf = writeClassicPcap({ header: { format: CaptureFormat.ClassicPcap, endian: 0, timestampResolution: 0,
      versionMajor: 2, versionMinor: 4, snapLen: 65535, linkType: 1, tzOffset: 0, sigfigs: 0 }, packets })
    const session = await processCapture({ blob: new Blob([buf]), fileName: 'sip.pcap', format: CaptureFormat.ClassicPcap,
      policy: profileToSanitizationPolicy(createPresetProfile('diagnostic')), generationId: 'g', sourceId: 's' })
    const container = containerFromWire(structuredClone(containerMetadataFromSessionTransferable(session).wire))
    expect(container.packetDiscovery).toEqual([])
    const rebuilt = sourceDiscoveryFromWire(discoveryToWire(session.discovery), container.packetDiscovery, container.coverageRollup)
    for (const protocol of ['ethernet', 'ipv4', 'udp', 'sip', 'sdp']) {
      expect(packetHasProtocol(rebuilt.unifiedCoverage, 0, protocol), protocol).toBe(true)
      expect(packetHasProtocol(rebuilt.unifiedCoverage, 1, protocol), protocol).toBe(true)
    }
    expect(packetHasProtocol(rebuilt.unifiedCoverage, 0, 'dns')).toBe(false)
    const protocols = coverageRowsFromProtocolSummaries(rebuilt.unifiedCoverage.byProtocol, 'diagnostic')
    expect(protocols.find(p => p.protocol === 'sip')?.recognizedPacketCount).toBe(2)
    expect(protocols.find(p => p.protocol === 'sdp')?.recognizedPacketCount).toBe(2)
    const direct = buildSessionCoverage({ packetCount: packets.length, analysis: session.discovery.analysis, packetDiscovery: session.discovery.packetDiscovery })
    const directRows = coverageRowsFromProtocolSummaries(direct.unifiedCoverage.byProtocol, 'diagnostic')
    // The outcome only reads incidents from the plan on this path.
    const plan = { incidents: undefined } as Parameters<typeof buildAnonymizationOutcome>[0]['plan']
    const outcome = buildAnonymizationOutcome({ protocols, gate: 'AI_READY', plan, preset: 'diagnostic' })
    const directOutcome = buildAnonymizationOutcome({ protocols: directRows, gate: 'AI_READY', plan, preset: 'diagnostic' })
    expect(outcome.families.map(f => [f.familyId, f.packetCount, f.state]).sort()).toEqual(directOutcome.families.map(f => [f.familyId, f.packetCount, f.state]).sort())
    expect(outcome.families.map(f => f.familyId).sort()).toEqual(['network-headers', 'sdp', 'sip'])
    expect(outcome.families.every(f => f.packetCount === 2)).toBe(true)
    expect(outcome.families.every(f => f.state === 'anonymized'), JSON.stringify(protocols.filter(p => p.recognizedPacketCount > 0))).toBe(true)
    expect(outcome.summarySentence).not.toMatch(/VPN|DHCP|DNS|HTTP|DMR/)
  })
  it('round-trips descriptors through pack/unpack', () => {
    const packets = [ethPacket(0), ethPacket(1), ethPacket(2)]
    const buf = writeClassicPcap({
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
    // descriptors come from a real parse — use processCapture for fidelity
    return processCapture({
      blob: new Blob([buf]),
      fileName: 'packed-rt.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: profileToSanitizationPolicy(createPresetProfile('diagnostic')),
      generationId: 'packed-rt',
      sourceId: 'packed-rt',
    }).then((session) => {
      const packed = packDescriptors(session.descriptors)
      const unpacked = unpackDescriptors(packed)
      expect(unpacked).toHaveLength(session.descriptors.length)
      for (let i = 0; i < unpacked.length; i++) {
        expect(unpacked[i]!.packetNumber).toBe(session.descriptors[i]!.packetNumber)
        expect(unpacked[i]!.timestamp.ticks).toBe(session.descriptors[i]!.timestamp.ticks)
        expect(unpacked[i]!.capturedLength).toBe(session.descriptors[i]!.capturedLength)
        expect(unpacked[i]!.fileOffset).toBe(session.descriptors[i]!.fileOffset)
      }
    })
  })

  it('transferable container unpacks to equivalent discovery coverage and unique identity intents', async () => {
    const packets = Array.from({ length: 40 }, (_, i) => ethPacket(i))
    const buf = writeClassicPcap({
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
    const session = await processCapture({
      blob: new Blob([buf]),
      fileName: 'packed-scale.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: profileToSanitizationPolicy(createPresetProfile('diagnostic')),
      generationId: 'packed-scale',
      sourceId: 'packed-scale',
    })

    const legacy = containerMetadataFromSession(session)
    const { wire, transfers } = containerMetadataFromSessionTransferable(session)
    expect(wire.packed).toBeDefined()
    expect(transfers.length).toBeGreaterThan(0)
    expect(wire.descriptors).toEqual([])
    expect(wire.packetDiscovery).toEqual([])

    const cloned = structuredClone(wire, { transfer: transfers })
    expect(wire.packed!.coverageRollup.packetProtocols!.offsets.byteLength).toBe(0)
    expect(wire.packed!.coverageRollup.packetProtocols!.protocolIds.byteLength).toBe(0)
    const fromPacked = containerFromWire(cloned)
    expect(fromPacked.coverageRollup!.packetProtocols!.offsets.length).toBe(packets.length + 1)
    const fromLegacy = containerFromWire(legacy)
    expect(fromPacked.descriptors.length).toBe(fromLegacy.descriptors.length)
    // Packed discover path keeps per-span coverage in the worker; UI gets rollup totals.
    expect(fromPacked.packetDiscovery).toEqual([])
    expect(fromPacked.coverageRollup).toBeDefined()
    expect(fromPacked.coverageRollup!.discoveryIssueCount).toBeGreaterThan(0)
    expect(fromLegacy.packetDiscovery.length).toBe(session.discovery.packetDiscovery.length)

    const compact = discoveryToWire(session.discovery)
    const full = discoveryToWire(session.discovery, { uniqueIdentityIntents: false })
    expect(compact.intentCount).toBe(full.intentCount)
    expect(compact.intents.length).toBeLessThanOrEqual(full.intents.length)
    expect(compact.intents.length).toBeGreaterThan(0)
    // Unique seeds must cover every distinct identity key present in the full list.
    const keyOf = (i: (typeof full.intents)[number]) =>
      `${i.category}:${i.canonical}:${JSON.stringify(i.constraint)}:${i.originalSpelling ?? ''}`
    expect(new Set(compact.intents.map(keyOf)).size).toBe(new Set(full.intents.map(keyOf)).size)
  })
})
