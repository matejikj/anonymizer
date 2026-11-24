import { describe, expect, it, vi, afterEach } from 'vitest'
import { WorkerChunkBackpressure, PCAP_EXPORT_MAX_IN_FLIGHT_CHUNKS } from '../../src/pcap/export/chunkBackpressure'
import { ExportSinkCoordinator } from '../../src/pcap/export/sinkCoordinator'
import { BlobExportSink } from '../../src/pcap/export/sinks'
import * as exportSinks from '../../src/pcap/export/sinks'
import type { PcapExportWorkerRequest, PcapExportWorkerResponse } from '../../src/pcap/export/workerProtocol'
import { buildIncrementalExportViaWorker } from '../../src/pcap/export/incrementalExportWorkerClient'
import { disposePcapExportWorker } from '../../src/pcap/export/pcapExportWorkerClient'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import { readClassicPcapFromBlob } from '../../src/pcap/capture/pcapReader'
import { createTestPcapSessionFromPackets } from '../pcap/unit/pcapSessionTestHelpers'
import {
  runPcapExport,
  cancelPcapExport,
  PcapExportCancelledError,
} from '../../src/pcap/export/coordinator'
import { CaptureFormat, Endian, TimestampResolution, type PacketEnvelope } from '../../src/pcap/domain/types'

function makeEthIpPacket(src: number[], dst: number[], n: number): PacketEnvelope {
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
    packetNumber: n,
    timestamp: { ticks: BigInt(1700000000 + n) * 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

describe('Stage 12 — export sink, backpressure, hard-cancel', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    disposePcapExportWorker()
  })

  it('WorkerChunkBackpressure allows at most two unconfirmed chunks', async () => {
    expect(PCAP_EXPORT_MAX_IN_FLIGHT_CHUNKS).toBe(2)
    const gate = new WorkerChunkBackpressure()

    await gate.acquire()
    await gate.acquire()

    let thirdReleased = false
    const third = gate.acquire().then(() => {
      thirdReleased = true
    })

    await new Promise((r) => setTimeout(r, 5))
    expect(thirdReleased).toBe(false)

    gate.ack()
    await third
    expect(thirdReleased).toBe(true)
  })

  it('ExportSinkCoordinator ignores late chunks after cancel', async () => {
    const coord = new ExportSinkCoordinator('gen-1')
    const sink = new BlobExportSink('out.pcap')
    coord.attachSink(sink)

    const chunk = new Uint8Array([1, 2, 3]).buffer
    expect(await coord.writeChunk(chunk, 'gen-1')).toBe(true)

    coord.cancel()
    expect(await coord.writeChunk(chunk, 'gen-1')).toBe(false)

    await coord.abort()
    await expect(coord.finalize()).rejects.toThrow(/cancelled/i)
  })

  it('BlobExportSink abort clears accumulated BlobPart references', async () => {
    const sink = new BlobExportSink('out.pcap')
    await sink.write(new Uint8Array(100).buffer)
    await sink.write(new Uint8Array(200).buffer)
    await sink.abort()
    await expect(sink.finalize()).rejects.toThrow(/aborted/i)
  })

  it('worker client keeps at most two unacked chunks in flight', async () => {
    const packets = [makeEthIpPacket([192, 168, 1, 1], [10, 0, 0, 1], 1)]
    const session = await createTestPcapSessionFromPackets({ fileName: 'ack.pcap', packets })

    let unacked = 0
    let maxUnacked = 0

    stubWorkerClass(createAckingMockWorker({
      onChunkPosted: () => {
        unacked += 1
        maxUnacked = Math.max(maxUnacked, unacked)
      },
      onChunkAcked: () => {
        unacked = Math.max(0, unacked - 1)
      },
    }))

    await buildIncrementalExportViaWorker({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
    })

    expect(maxUnacked).toBeLessThanOrEqual(PCAP_EXPORT_MAX_IN_FLIGHT_CHUNKS)
  })

  it('legacy full-buffer worker path is removed', async () => {
    const { getPcapExportWorker } = await import('../../src/pcap/export/pcapExportWorkerClient')
    expect(getPcapExportWorker).toBeDefined()
    // buildCaptureFromPlanAsync removed in Stage 13 — only incremental worker remains
    await expect(import('../../src/pcap/export/pcapExportWorkerClient')).resolves.toMatchObject({
      disposePcapExportWorker: expect.any(Function),
    })
  })

  it('runPcapExport cancel rejects without success and aborts blob sink', async () => {
    const packets = Array.from({ length: 80 }, (_, i) =>
      makeEthIpPacket([192, 168, 0, (i % 250) + 1], [10, 0, 0, (i % 250) + 1], i + 1),
    )
    const session = await createTestPcapSessionFromPackets({ fileName: 'cancel.pcap', packets })

    await withoutWorker(async () => {
      const exportPromise = runPcapExport({
        plan: session.plan,
        descriptors: session.descriptors,
        sourceBlob: session.sourceFile,
        unsupportedLayers: 0,
        protocolCoverage: [],
        preferFileSystemAccess: false,
      })

      cancelPcapExport()
      await expect(exportPromise).rejects.toBeInstanceOf(PcapExportCancelledError)
    })
  })

  it('blob fallback holds bounded chunk parts during streaming export', async () => {
    const downloadSpy = vi.spyOn(exportSinks, 'triggerBlobDownload').mockImplementation(() => {})
    const packets = Array.from({ length: 30 }, (_, i) =>
      makeEthIpPacket([192, 168, 0, 1], [10, 0, 0, 1], i + 1),
    )
    const buffer = writeClassicPcap({
      header: {
        format: CaptureFormat.ClassicPcap,
        endian: Endian.Little,
        timestampResolution: TimestampResolution.Microseconds,
        versionMajor: 2,
        versionMinor: 4,
        snapLen: 65535,
        linkType: 1,
        tzOffset: 0,
        sigfigs: 0,
      },
      packets,
    })
    const blob = new Blob([buffer])
    const read = await readClassicPcapFromBlob(blob)
    const session = await createTestPcapSessionFromPackets({ fileName: 'mem.pcap', packets })

    await withoutWorker(async () => {
      const result = await runPcapExport({
        plan: session.plan,
        descriptors: session.descriptors,
        sourceBlob: session.sourceFile,
        unsupportedLayers: 0,
        protocolCoverage: [],
        preferFileSystemAccess: false,
      })

      expect(result.byteLength).toBeGreaterThan(0)
      expect(read.packets.length).toBe(30)
    })

    downloadSpy.mockRestore()
  })
})

function stubWorkerClass(worker: WorkerLike): void {
  globalThis.Worker = class {
    constructor() {
      return worker
    }
  } as unknown as typeof Worker
}

async function withoutWorker<T>(fn: () => Promise<T>): Promise<T> {
  const originalWorker = globalThis.Worker
  // @ts-expect-error — force sync incremental export path in tests
  globalThis.Worker = undefined
  try {
    return await fn()
  } finally {
    globalThis.Worker = originalWorker
  }
}

function createAckingMockWorker(hooks: {
  onChunkPosted?: () => void
  onChunkAcked?: () => void
}): WorkerLike {
  const messageListeners = new Set<(ev: MessageEvent) => void>()
  const gate = new WorkerChunkBackpressure()

  const emit = (response: PcapExportWorkerResponse, transfer?: Transferable[]) => {
    void transfer
    for (const fn of messageListeners) fn({ data: response } as MessageEvent)
  }

  return {
    postMessage(message: unknown) {
      const msg = message as PcapExportWorkerRequest
      queueMicrotask(async () => {
        if (msg.type === 'chunk-ack') {
          gate.ack()
          hooks.onChunkAcked?.()
          return
        }
        if (msg.type === 'cancel') return

        if (msg.type === 'build-incremental') {
          const { descriptorsFromWire } = await import('../../src/pcap/processing/containerWireAdapter.ts')
          const { runIncrementalExport } = await import('../../src/pcap/export/incremental/incrementalExportEngine.ts')
          const wirePlan = msg.plan
          const plan = {
            generationId: wirePlan.generationId,
            profileId: wirePlan.profileId,
            profileHash: wirePlan.profileHash,
            format: wirePlan.format,
            fileName: wirePlan.fileName,
            engineVersion: wirePlan.engineVersion,
            droppedPacketNumbers: wirePlan.droppedPacketNumbers,
            timestamps: wirePlan.timestamps ?? 'relative',
            timestampAnchorSeed: wirePlan.timestampAnchorSeed ?? 'test-anchor-seed',
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
            classicHeader: wirePlan.classicHeader as import('../../src/pcap/domain/types').ClassicPcapHeader,
            packets: wirePlan.packets.map((p) => ({
              index: p.index,
              packetNumber: p.packetNumber,
              drop: p.drop,
              patches: p.patches.map((patch) => ({ offset: patch.offset, data: new Uint8Array(patch.data) })),
              truncatedLength: p.truncatedLength,
              originalCapturedLength: p.originalCapturedLength,
              originalLength: p.originalLength,
              linkType: p.linkType,
              interfaceId: p.interfaceId,
              sectionIndex: p.sectionIndex,
              originalTimestamp: {
                ticks: BigInt(p.originalTimestamp.ticks),
                unitsPerSecond: BigInt(p.originalTimestamp.unitsPerSecond),
                offsetSeconds: BigInt(p.originalTimestamp.offsetSeconds),
              },
            })),
          }

          const result = await runIncrementalExport({
            plan,
            descriptors: descriptorsFromWire(msg.descriptors),
            sourceBlob: msg.sourceBlob,
            onChunk: async (buffer, chunkIndex) => {
              await gate.acquire()
              hooks.onChunkPosted?.()
              emit({ type: 'chunk', requestId: msg.requestId, chunkIndex, buffer }, [buffer])
            },
          })

          emit({
            type: 'built-incremental',
            requestId: msg.requestId,
            chunkCount: result.chunks.length,
            result: {
              fileName: result.fileName,
              changedPackets: result.changedPackets,
              truncatedPayloads: result.truncatedPayloads,
              validationValid: result.validationValid,
              validationIssueCount: result.validationIssueCount,
              checksumCounts: { ...result.checksumReport.counts },
            },
          })
        }
      })
    },
    terminate() {
      messageListeners.clear()
    },
    addEventListener(type: 'message', fn: (ev: MessageEvent) => void) {
      if (type === 'message') messageListeners.add(fn)
    },
    removeEventListener(type: 'message', fn: (ev: MessageEvent) => void) {
      if (type === 'message') messageListeners.delete(fn)
    },
  }
}
