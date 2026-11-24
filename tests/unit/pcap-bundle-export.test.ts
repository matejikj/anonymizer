import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import type { PacketEnvelope } from '../../src/pcap/domain/types'
import { createDefaultPcapProfile } from '../../src/pcap/profile/presets'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import {
  getSharedMappingClient,
  resetSharedMappingClient,
  setSharedMappingClientForTests,
} from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { exportActiveMappingBundle } from '../../src/features/mapping-bundle/bundleController'
import { createTestPcapSessionFromPackets } from '../pcap/unit/pcapSessionTestHelpers'
import { orchestrateInProcess } from '../../src/pcap/processing/processingOrchestrator'
import { CaptureFormat } from '../../src/pcap/domain/types'
import { policyFromPreset } from '../../src/pcap/sanitize/engine'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'

vi.mock('../../src/features/export-log/exportCoordinator.ts', () => ({
  downloadBlob: vi.fn(),
}))

function packetWithIp(): PacketEnvelope {
  const payload = new TextEncoder().encode('probe')
  const data = new Uint8Array(14 + 20 + 8 + payload.length)
  data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  data[16] = 0
  data[17] = 28 + payload.length
  data[23] = 17
  data.set([10, 0, 0, 8], 26)
  data.set([192, 168, 1, 1], 30)
  data.set(payload, 42)
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

describe('PCAP mapping bundle export', () => {
  beforeEach(() => {
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
  })

  afterEach(() => {
    resetSharedMappingClient()
  })

  it('orchestrateInProcess publishes mapping on shared client', async () => {
    const pkt = packetWithIp()
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
      packets: [pkt],
    })
    const blob = new Blob([buffer])

    await orchestrateInProcess({
      blob,
      fileName: 'bundle.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('diagnostic'),
      profile: createDefaultPcapProfile().profile,
      generationId: 'pcap-gen-1',
      sourceId: 'bundle.pcap',
      mappingClient: getSharedMappingClient(),
    })

    const snapshot = getSharedMappingClient().getPublishedSnapshot()
    expect(snapshot).not.toBeNull()
    expect(snapshot!.entries.length).toBeGreaterThan(0)
  })

  it('exports mapping bundle JSON for active PCAP session', async () => {
    await createTestPcapSessionFromPackets({
      fileName: 'export.pcap',
      packets: [packetWithIp()],
      profile: createDefaultPcapProfile().profile,
    })

    await getSharedMappingClient().resolve('test-gen', 'export.pcap', [
      { category: 'ipv4', canonical: '10.0.0.8', constraint: { kind: 'ipv4-wire' } },
    ])

    const result = await exportActiveMappingBundle({ mode: 'pcap' })
    expect(result.fileName).toMatch(/\.rnd-mapping-bundle\.json$/)

    const { downloadBlob } = await import('../../src/features/export-log/exportCoordinator.ts')
    const blobArg = (downloadBlob as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[1] as Blob
    const text = await blobArg.text()
    expect(text).toContain('"canonical": "10.0.0.8"')
  })
})
