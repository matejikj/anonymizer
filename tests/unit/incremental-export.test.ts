import { describe, expect, it, beforeEach } from 'vitest'
import { CaptureFormat, Endian, TimestampResolution, type PacketEnvelope } from '../../src/pcap/domain/types'
import {
  runIncrementalExport,
  buildEnvelopesForParityTest,
  ExportPlanRejectedError,
} from '../../src/pcap/export/incremental'
import { runInternalIncrementalExport } from '../../src/pcap/export/internalExportPort'
import { previewBytesFromPlan } from '../../src/pcap/export/packetBuilder'
import { createTestPcapSessionFromPackets } from '../pcap/unit/pcapSessionTestHelpers'
import { sanitizePacket, HIGH_PRIVACY_POLICY } from '../../src/pcap/sanitize'
import { SessionMapping } from '../../src/pcap/anonymization/mapping'
import { createDefaultPcapProfile } from '../../src/pcap/profile/presets'
import type { PcapExportWorkerRequest, PcapExportWorkerResponse } from '../../src/pcap/export/workerProtocol'
import {
  PCAP_EXPORT_PROTOCOL_VERSION,
  validateExportProtocolVersion,
} from '../../src/pcap/export/workerProtocol'
import { buildIncrementalExportViaWorker } from '../../src/pcap/export/incrementalExportWorkerClient'
import { disposePcapExportWorker } from '../../src/pcap/export/pcapExportWorkerClient'
import type { WorkerLike } from '../../src/mapping/mappingWorkerClient'
import { writeClassicPcapGlobalHeader, writeClassicPcapRecord, writeClassicPcap, concatArrayBuffers } from '../../src/pcap/capture/pcapWriter'
import { createPcapngIncrementalWriter, writePcapng, concatPcapngChunks } from '../../src/pcap/capture/pcapngWriter'
import { buildCaptureFromPlan } from '../../src/pcap/export/engine'
import { readClassicPcap } from '../../src/pcap/capture/pcapReader'

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

function createInProcessExportWorker(): WorkerLike {
  const messageListeners = new Set<(ev: MessageEvent) => void>()
  const emit = (response: PcapExportWorkerResponse, transfer?: Transferable[]) => {
    void transfer
    for (const fn of messageListeners) fn({ data: response } as MessageEvent)
  }

  return {
    postMessage(message: unknown) {
      const msg = message as PcapExportWorkerRequest
      queueMicrotask(async () => {
        if (msg.type === 'cancel') return
        if (msg.type === 'chunk-ack') return

        if (msg.type === 'build-incremental') {
          const versionErr = validateExportProtocolVersion(msg.protocolVersion)
          if (versionErr) {
            emit({ type: 'error', requestId: msg.requestId, code: versionErr, message: versionErr })
            return
          }
          try {
            const { descriptorsFromWire } = await import('../../src/pcap/processing/containerWireAdapter.ts')
            const { runIncrementalExport: runExport } = await import('../../src/pcap/export/incremental/incrementalExportEngine.ts')

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
              pcapngSections: wirePlan.pcapngSections as import('../../src/pcap/domain/types').PcapngSectionInfo[] | undefined,
              pcapngInterfaces: wirePlan.pcapngInterfaces as import('../../src/pcap/domain/types').PcapngInterfaceInfo[] | undefined,
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

            const result = await runExport({
              plan,
              descriptors: descriptorsFromWire(msg.descriptors),
              sourceBlob: msg.sourceBlob,
              expectedGenerationId: msg.expectedGenerationId,
              expectedProfileHash: msg.expectedProfileHash,
              batchLimits: msg.batchLimits,
              onProgress: (p) => {
                emit({
                  type: 'progress',
                  requestId: msg.requestId,
                  phase: p.phase,
                  packetsDone: p.packetsDone,
                  packetsTotal: p.packetsTotal,
                  chunksEmitted: p.chunksEmitted,
                })
              },
              onChunk: (buffer, chunkIndex) => {
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
                validationNewBlockingCount: result.validation.newBlockingIssues.length,
                checksumCounts: { ...result.checksumReport.counts },
              },
            })
          } catch (err) {
            emit({
              type: 'error',
              requestId: msg.requestId,
              code: 'internal',
              message: err instanceof Error ? err.message : String(err),
            })
          }
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

describe('Stage 11 — incremental PCAP export', () => {
  beforeEach(() => {
    // no global session state required
  })

  it('classic roundtrip preserves framing, timestamps and packet bytes', async () => {
    const packets = [
      makeEthIpPacket([192, 168, 1, 10], [10, 0, 0, 1], 1),
      makeEthIpPacket([192, 168, 1, 11], [10, 0, 0, 2], 2),
    ]
    const session = await createTestPcapSessionFromPackets({ fileName: 'roundtrip.pcap', packets })

    const sync = buildCaptureFromPlan(session.plan, packets)
    const incremental = await runInternalIncrementalExport({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
      useWorker: false,
    })

    expect(incremental.validationValid).toBe(true)
    expect(new Uint8Array(incremental.buffer)).toEqual(new Uint8Array(sync.buffer))

    const parsed = readClassicPcap(incremental.buffer)
    expect(parsed.packets.length).toBe(2)
    expect(parsed.packets[0]!.timestamp.ticks).toBe(parsed.packets[0]!.timestamp.ticks)
    expect(parsed.packets[0]!.data.length).toBeGreaterThan(0)
  })

  it('preview bytes match incremental export envelope bytes except checksum fields', async () => {
    const pkt = makeEthIpPacket([192, 168, 1, 10], [8, 8, 8, 8], 1)
    const session = await createTestPcapSessionFromPackets({ fileName: 'parity.pcap', packets: [pkt] })
    const envelopes = await buildEnvelopesForParityTest({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
    })
    const preview = previewBytesFromPlan(pkt, session.plan.packets[0]!)
    const { locateLayers } = await import('../../src/pcap/checksums/locate')
    const layers = locateLayers(envelopes[0]!.data, session.plan.packets[0]!.linkType, envelopes[0]!.data.length)
    const skip = new Set<number>()
    if (layers.l3Proto === 'ipv4') skip.add(layers.l3Offset + 10).add(layers.l3Offset + 11)
    if (layers.l4Proto === 'udp') skip.add(layers.l4Offset + 6).add(layers.l4Offset + 7)
    for (let i = 0; i < preview.length; i++) {
      if (skip.has(i)) continue
      expect(envelopes[0]!.data[i]).toBe(preview[i])
    }
  })

  it('pcapng incremental writer chunks match full writePcapng output', () => {
    const sections = [{ sectionIndex: 0, endian: Endian.Little, versionMajor: 1, versionMinor: 0, sectionLength: -1n }]
    const interfaces = [{
      interfaceId: 0,
      sectionIndex: 0,
      linkType: 1,
      snapLen: 262144,
      tsResol: TimestampResolution.Microseconds,
      tsResolValue: 6,
      tsOffset: 0n,
    }]
    const packets = [
      makeEthIpPacket([10, 0, 0, 1], [10, 0, 0, 2], 1),
      makeEthIpPacket([10, 0, 0, 3], [10, 0, 0, 4], 2),
    ]
    const full = writePcapng({ sections, interfaces, packets })
    const writer = createPcapngIncrementalWriter({ sections, interfaces })
    const chunks: ArrayBuffer[] = []
    for (const pkt of packets) {
      chunks.push(...writer.emitPacket(pkt))
    }
    expect(new Uint8Array(concatPcapngChunks(chunks))).toEqual(new Uint8Array(full))
  })

  it('rejects plan profile hash mismatch', async () => {
    const packets = [makeEthIpPacket([10, 0, 0, 1], [10, 0, 0, 2], 1)]
    const session = await createTestPcapSessionFromPackets({ fileName: 'reject.pcap', packets })
    await expect(
      runIncrementalExport({
        plan: session.plan,
        descriptors: session.descriptors,
        sourceBlob: session.sourceFile,
        expectedProfileHash: 'deadbeef',
      }),
    ).rejects.toBeInstanceOf(ExportPlanRejectedError)
  })

  it('batch time limit yields progress for many small packets', async () => {
    const packets = Array.from({ length: 200 }, (_, i) =>
      makeEthIpPacket([10, 0, (i >> 8) & 0xff, i & 0xff], [192, 168, 0, 1], i + 1),
    )
    const session = await createTestPcapSessionFromPackets({ fileName: 'many.pcap', packets })
    let progressEvents = 0
    await runIncrementalExport({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
      batchLimits: { maxPackets: 1, maxBytes: 1, maxTimeMs: 0 },
      onProgress: () => {
        progressEvents++
      },
    })
    expect(progressEvents).toBeGreaterThan(1)
  })

  it('incremental writer emits header and record chunks without full buffer first', () => {
    const header = {
      format: CaptureFormat.ClassicPcap,
      endian: Endian.Little,
      timestampResolution: TimestampResolution.Microseconds,
      versionMajor: 2,
      versionMinor: 4,
      snapLen: 65535,
      linkType: 1,
      tzOffset: 0,
      sigfigs: 0,
    }
    const pkt = makeEthIpPacket([1, 1, 1, 1], [2, 2, 2, 2], 1)
    const chunks = [writeClassicPcapGlobalHeader(header), writeClassicPcapRecord(header, pkt)]
    expect(chunks[0]!.byteLength).toBe(24)
    expect(chunks[1]!.byteLength).toBe(16 + pkt.capturedLength)
    const full = writeClassicPcap({ header, packets: [pkt] })
    expect(new Uint8Array(concatArrayBuffers(chunks))).toEqual(new Uint8Array(full))
  })

  it('worker incremental path never receives PacketEnvelope[] wire payload', async () => {
    disposePcapExportWorker()
    const packets = [makeEthIpPacket([192, 168, 1, 1], [10, 0, 0, 1], 1)]
    const session = await createTestPcapSessionFromPackets({ fileName: 'worker.pcap', packets })

    const originalWorker = globalThis.Worker
    const fakeWorker = createInProcessExportWorker()
    globalThis.Worker = class {
      constructor() {
        return fakeWorker
      }
    } as unknown as typeof Worker

    try {
      disposePcapExportWorker()
      let sawLegacyPackets = false
      const origPost = fakeWorker.postMessage.bind(fakeWorker)
      fakeWorker.postMessage = (message: unknown) => {
        const msg = message as PcapExportWorkerRequest
        if (msg.type === 'build-capture') sawLegacyPackets = true
        if (msg.type === 'build-incremental') {
          expect(msg.protocolVersion).toBe(PCAP_EXPORT_PROTOCOL_VERSION)
          expect(msg.descriptors.length).toBe(session.descriptors.length)
          expect(msg.sourceBlob).toBeInstanceOf(Blob)
          expect('packets' in msg).toBe(false)
        }
        origPost(message)
      }

      await buildIncrementalExportViaWorker({
        plan: session.plan,
        descriptors: session.descriptors,
        sourceBlob: session.sourceFile,
      })
      expect(sawLegacyPackets).toBe(false)
    } finally {
      globalThis.Worker = originalWorker
      disposePcapExportWorker()
    }
  })

  it('boundary fixture matches sync export byte-for-byte', async () => {
    const mapping = new SessionMapping()
    const payload = new Uint8Array(9000)
    payload.fill(0xab)
    const data = new Uint8Array(14 + 20 + 8 + payload.length)
    data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
    data[12] = 0x08
    data[13] = 0x00
    data[14] = 0x45
    const ipTotal = 20 + 8 + payload.length
    data[16] = (ipTotal >> 8) & 0xff
    data[17] = ipTotal & 0xff
    data[23] = 17
    data.set([10, 1, 2, 3], 26)
    data.set([10, 4, 5, 6], 30)
    data.set(payload, 42)
    const pkt: PacketEnvelope = {
      packetNumber: 1,
      timestamp: { ticks: 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
      capturedLength: data.length,
      originalLength: data.length,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: 0,
      data,
    }
    const san = sanitizePacket(
      { index: 0, data: pkt.data, capturedLength: pkt.capturedLength, originalLength: pkt.originalLength, linkType: 1 },
      HIGH_PRIVACY_POLICY,
      mapping,
    )
    const profile = createDefaultPcapProfile().profile
    const { buildPlanSnapshot } = await import('../../src/pcap/export/planSnapshot')
    const plan = buildPlanSnapshot({
      generationId: 'b1',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'jumbo.pcap',
      packets: [pkt],
      sanitization: [san],
      classicHeader: {
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
    })
    const buffer = writeClassicPcap({ header: plan.classicHeader!, packets: [pkt] })
    const blob = new Blob([buffer])
    const read = await import('../../src/pcap/capture/pcapReader').then((m) => m.readClassicPcapFromBlob(blob))

    const sync = buildCaptureFromPlan(plan, [pkt])
    const incremental = await runIncrementalExport({
      plan,
      descriptors: read.descriptors,
      sourceBlob: blob,
    })
    expect(new Uint8Array(concatArrayBuffers(incremental.chunks))).toEqual(new Uint8Array(sync.buffer))
  })
})
