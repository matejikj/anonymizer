import { describe, expect, it, afterEach } from 'vitest'
import { CaptureFormat } from '../../src/pcap/domain/types.ts'
import { policyFromPreset } from '../../src/pcap/sanitize/engine.ts'
import { processCapture } from '../../src/pcap/processing/processingPipeline.ts'
import { loadPcapViaProcessingWorker } from '../../src/pcap/processing/pcapWorkerLoadPort.ts'
import { MappingAuthority } from '../../src/mapping/mappingAuthority.ts'
import { MappingWorkerClient, type WorkerLike } from '../../src/mapping/mappingWorkerClient.ts'
import { PcapProcessingWorkerClient } from '../../src/pcap/processing/pcapProcessingWorkerClient.ts'
import {
  PCAP_PROCESSING_PROTOCOL_VERSION,
  validateProcessingProtocolVersion,
  type PcapProcessingWorkerRequest,
  type PcapProcessingWorkerResponse,
} from '../../src/pcap/processing/workerProtocol.ts'
import {
  validateProtocolVersion,
  validateResolveIdentities,
  snapshotToWire,
  type MappingWorkerRequest,
  type MappingWorkerResponse,
} from '../../src/mapping/protocol.ts'
import {
  setProcessingClientsForTests,
  resetProcessingClients,
} from '../../src/pcap/processing/processingOrchestrator.ts'
import { PCAP_MAGIC_MICRO_LE } from '../../src/pcap/domain/types.ts'

function makePcapBlob(): Blob {
  const packetData = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
  const size = 24 + 16 + packetData.length
  const buf = new ArrayBuffer(size)
  const view = new DataView(buf)
  view.setUint32(0, PCAP_MAGIC_MICRO_LE, true)
  view.setUint16(4, 2, true)
  view.setUint16(6, 4, true)
  view.setUint32(16, 65535, true)
  view.setUint32(20, 1, true)
  view.setUint32(24 + 8, packetData.length, true)
  view.setUint32(24 + 12, packetData.length, true)
  new Uint8Array(buf, 24 + 16, packetData.length).set(packetData)
  return new Blob([buf])
}

function createInProcessProcessingWorker(): () => WorkerLike {
  return () => {
    const listeners = new Set<(ev: MessageEvent) => void>()
    const emit = (response: PcapProcessingWorkerResponse) => {
      for (const fn of listeners) fn({ data: response } as MessageEvent)
    }

    let cachedSession: Awaited<ReturnType<typeof processCapture>> | null = null

    return {
      postMessage(message: unknown) {
        const msg = message as PcapProcessingWorkerRequest
        queueMicrotask(async () => {
          const versionErr = validateProcessingProtocolVersion(msg.protocolVersion)
          if (versionErr) {
            emit({ type: 'error', requestId: msg.requestId, code: versionErr, message: versionErr })
            return
          }

          if (msg.type === 'cancel') return

          if (msg.type === 'process') {
            try {
              cachedSession = await processCapture({
                blob: msg.blob,
                fileName: 'test.pcap',
                format: msg.format,
                policy: msg.policy,
                generationId: msg.generationId,
                sourceId: msg.sourceId,
                batchSize: msg.batchSize,
              })
              const { discoveryToWire, containerMetadataFromSessionTransferable } = await import('../../src/pcap/processing/processingPipeline.ts')
              const { wire: container } = containerMetadataFromSessionTransferable(cachedSession)
              emit({
                type: 'discovered',
                requestId: msg.requestId,
                generationId: msg.generationId,
                discovery: discoveryToWire(cachedSession.discovery),
                container,
              })
            } catch (err) {
              emit({
                type: 'error',
                requestId: msg.requestId,
                generationId: msg.generationId,
                code: 'parse-failed',
                message: err instanceof Error ? err.message : 'failed',
              })
            }
            return
          }

          if (msg.type === 'build-plan' && cachedSession) {
            const { buildPlanFromWireSnapshot } = await import('../../src/pcap/processing/processingPipeline.ts')
            const { planToWireExport } = await import('../../src/pcap/processing/planWireAdapter.ts')
            const plan = buildPlanFromWireSnapshot(cachedSession, msg.snapshot, msg.profile as import('../../src/pcap/profile/schema.ts').PcapProfile)
            emit({
              type: 'plan-built',
              requestId: msg.requestId,
              generationId: msg.generationId,
              plan: planToWireExport(plan).wire,
            })
          }
        })
      },
      terminate() { listeners.clear() },
      addEventListener(_: 'message', fn: (ev: MessageEvent) => void) { listeners.add(fn) },
      removeEventListener(_: 'message', fn: (ev: MessageEvent) => void) { listeners.delete(fn) },
    }
  }
}

function createInProcessMappingWorker(): () => WorkerLike {
  const authority = new MappingAuthority()
  return () => {
    const listeners = new Set<(ev: MessageEvent) => void>()
    const emit = (response: MappingWorkerResponse) => {
      for (const fn of listeners) fn({ data: response } as MessageEvent)
    }
    return {
      postMessage(message: unknown) {
        const msg = message as MappingWorkerRequest
        queueMicrotask(() => {
          if (msg.type === 'resolve') {
            const validated = validateResolveIdentities(msg.identities)
            if (!validated.ok) {
              emit({ type: 'error', requestId: msg.requestId, generationId: msg.generationId, code: validated.error.code, message: validated.error.message })
              return
            }
            const result = authority.resolve(
              { generationId: msg.generationId, sourceId: msg.sourceId, identities: validated.identities },
              msg.config,
            )
            if (!result.ok) {
              emit({ type: 'error', requestId: msg.requestId, generationId: msg.generationId, code: result.code, message: result.message })
              return
            }
            emit({ type: 'resolved', requestId: msg.requestId, generationId: msg.generationId, snapshot: snapshotToWire(result.snapshot) })
          }
        })
      },
      terminate() { listeners.clear() },
      addEventListener(_: 'message', fn: (ev: MessageEvent) => void) { listeners.add(fn) },
      removeEventListener(_: 'message', fn: (ev: MessageEvent) => void) { listeners.delete(fn) },
    }
  }
}

describe('PCAP processing worker path (Stage 8)', () => {
  afterEach(() => {
    resetProcessingClients()
  })

  it('production load path delegates to worker orchestration', async () => {
    const { readFile } = await import('node:fs/promises')
    const { fileURLToPath } = await import('node:url')
    const path = fileURLToPath(new URL('../../src/pcap/ui/pcapLoadController.ts', import.meta.url))
    const src = await readFile(path, 'utf8')
    expect(src).toContain('orchestrateViaWorkers')
    expect(src).not.toMatch(/runSessionSanitization/)
    expect(src).not.toMatch(/analyzePackets\s*\(/)
  })

  it('correlation PCAP adapter keeps packet payloads behind a worker boundary', async () => {
    const { readFile } = await import('node:fs/promises')
    const { fileURLToPath } = await import('node:url')
    const path = fileURLToPath(new URL('../../src/correlation/pcapSourceAdapter.ts', import.meta.url))
    const src = await readFile(path, 'utf8')

    expect(src).toContain('PcapProcessingWorkerClient')
    expect(src).not.toContain("from '../pcap/processing/processingPipeline'")
    expect(src).not.toMatch(/\bProcessingSession\b/)
    expect(src).not.toMatch(/\.packets\b/)
  })

  it('processCapture supports cancel via isCancelled', async () => {
    let cancelled = false
    const blob = makePcapBlob()
    await expect(processCapture({
      blob,
      fileName: 't.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('high-privacy'),
      generationId: 'g',
      sourceId: 's',
      isCancelled: () => cancelled,
    })).resolves.toBeDefined()

    cancelled = true
    await expect(processCapture({
      blob,
      fileName: 't.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('high-privacy'),
      generationId: 'g2',
      sourceId: 's',
      isCancelled: () => true,
    })).rejects.toThrow('cancelled')
  })
})
