import { describe, expect, it, afterEach, vi } from 'vitest'
import { CaptureFormat } from '../../src/pcap/domain/types.ts'
import { createDefaultPcapProfile, profileToSanitizationPolicy } from '../../src/pcap/profile/presets.ts'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter.ts'
import {
  orchestrateViaWorkers,
  setProcessingClientsForTests,
  resetProcessingClients,
} from '../../src/pcap/processing/processingOrchestrator.ts'
import { PcapProcessingWorkerClient } from '../../src/pcap/processing/pcapProcessingWorkerClient.ts'
import { createInProcessPcapProcessingClient } from '../../tests/helpers/inProcessPcapProcessingWorker.ts'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker.ts'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient.ts'
import type { PacketEnvelope } from '../../src/pcap/domain/types.ts'

function ethIpv4Packet(index: number, srcIp: [number, number, number, number], dstIp: [number, number, number, number]): PacketEnvelope {
  const data = new Uint8Array(54)
  data.set([0x00, 0x11, 0x22, 0x33, 0x44, index & 0xff], 0)
  data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  data[16] = 0
  data[17] = 40
  data[23] = 6
  data.set(srcIp, 26)
  data.set(dstIp, 30)
  const tcpOff = 34
  data[tcpOff] = 0x1f
  data[tcpOff + 1] = 0x90
  data[tcpOff + 2] = 0x00
  data[tcpOff + 3] = 0x50
  data[tcpOff + 12] = 0x50
  return {
    packetNumber: index,
    timestamp: { ticks: BigInt(index) * 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

describe('PF-03: orchestrateViaWorkers identity/intent fusion', () => {
  afterEach(() => {
    resetProcessingClients()
  })

  it('produces one consistent alias per repeated identity and a patch for every occurrence', async () => {
    setProcessingClientsForTests(
      createInProcessPcapProcessingClient(),
      new MappingWorkerClient(createInProcessMappingWorkerFactory()),
    )

    // 10.0.0.5 repeats across 3 packets (with a different destination each time), plus a
    // fourth packet with an unrelated pair — several occurrences, few unique identities.
    const packets = [
      ethIpv4Packet(0, [10, 0, 0, 5], [192, 168, 1, 1]),
      ethIpv4Packet(1, [10, 0, 0, 5], [192, 168, 1, 2]),
      ethIpv4Packet(2, [10, 0, 0, 5], [192, 168, 1, 1]),
      ethIpv4Packet(3, [172, 16, 0, 9], [172, 16, 0, 10]),
    ]
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
    const blob = new Blob([buf])

    const profile = createDefaultPcapProfile().profile
    const policy = profileToSanitizationPolicy(profile)

    const result = await orchestrateViaWorkers({
      blob,
      fileName: 'orchestrator-pf03.pcap',
      format: CaptureFormat.ClassicPcap,
      policy,
      profile,
      generationId: 'gen-pf03',
      sourceId: 'orchestrator-pf03.pcap',
    })

    // Every packet must have produced a plan entry with patches for its (mapped) IPs — no
    // occurrence lost by the single-pass intent/identity fusion.
    expect(result.planWire.packets.length).toBe(4)
    for (const pkt of result.planWire.packets) {
      expect(pkt.patches.length).toBeGreaterThan(0)
    }

    // 10.0.0.5 must resolve to exactly one alias, reused identically across packets 0 and 2
    // (same src IP patch bytes at the same offset in both).
    const srcIpOffset = 14 + 12 // ethernet(14) + ipv4 header src offset(12)
    const pkt0Src = result.planWire.packets[0]!.patches.find((p) => p.offset === srcIpOffset)
    const pkt2Src = result.planWire.packets[2]!.patches.find((p) => p.offset === srcIpOffset)
    expect(pkt0Src).toBeDefined()
    expect(pkt2Src).toBeDefined()
    expect(pkt0Src!.data).toEqual(pkt2Src!.data)

    // The snapshot must contain exactly the unique identities (5 IPs total: 10.0.0.5,
    // 192.168.1.1, 192.168.1.2, 172.18.0.9, 172.18.0.10 — plus MAC/port categories), never a
    // separate entry per occurrence.
    const ipv4Entries = result.snapshot.entries.filter((e) => e.category === 'ipv4')
    const uniqueCanonicals = new Set(ipv4Entries.map((e) => e.canonical))
    expect(ipv4Entries.length).toBe(uniqueCanonicals.size)
    expect(uniqueCanonicals.size).toBe(5)
  })

  it('forwards onProgress to both the processCapture and buildPlan worker-client calls', async () => {
    // Regression: orchestrateViaWorkers used to accept an `onProgress` callback from its
    // caller (the "Analyzuji pakety" load splash) but never actually pass it through to the
    // worker-client calls — `void input.onProgress` silently discarded it, so the splash's
    // packetsTotal/bytesDone never left their initial zero values and the progress bar looked
    // permanently stuck at "0 B / <file size>" for the whole load, no matter how long it took.
    setProcessingClientsForTests(
      createInProcessPcapProcessingClient(),
      new MappingWorkerClient(createInProcessMappingWorkerFactory()),
    )

    const processCaptureSpy = vi.spyOn(PcapProcessingWorkerClient.prototype, 'processCapture')
    const buildPlanSpy = vi.spyOn(PcapProcessingWorkerClient.prototype, 'buildPlan')

    const packets = [ethIpv4Packet(0, [10, 0, 0, 5], [192, 168, 1, 1])]
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
    const blob = new Blob([buf])
    const profile = createDefaultPcapProfile().profile
    const policy = profileToSanitizationPolicy(profile)
    const onProgress = vi.fn()

    await orchestrateViaWorkers({
      blob,
      fileName: 'orchestrator-progress.pcap',
      format: CaptureFormat.ClassicPcap,
      policy,
      profile,
      generationId: 'gen-progress',
      sourceId: 'orchestrator-progress.pcap',
      onProgress,
    })

    expect(processCaptureSpy).toHaveBeenCalledTimes(1)
    expect(processCaptureSpy.mock.calls[0]![0].onProgress).toBe(onProgress)
    expect(buildPlanSpy).toHaveBeenCalledTimes(1)
    expect(buildPlanSpy.mock.calls[0]![0].onProgress).toBe(onProgress)

    processCaptureSpy.mockRestore()
    buildPlanSpy.mockRestore()
  })
})
