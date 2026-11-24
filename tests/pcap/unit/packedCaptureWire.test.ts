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
import { profileToSanitizationPolicy, createPresetProfile } from '../../../src/pcap/profile/presets'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'

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

    const fromPacked = containerFromWire(wire)
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
