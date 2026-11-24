import {
  processCapture,
  buildPlanFromWireSnapshot,
  containerMetadataFromSessionTransferable,
  discoveryToWire,
} from '../../src/pcap/processing/processingPipeline'
import { PcapProcessingWorkerClient, type WorkerLike } from '../../src/pcap/processing/pcapProcessingWorkerClient'
import { planToWireExport } from '../../src/pcap/processing/planWireAdapter'
import {
  PCAP_PROCESSING_WORKER_ERROR,
  validateProcessingProtocolVersion,
  type PcapProcessingWorkerRequest,
  type PcapProcessingWorkerResponse,
} from '../../src/pcap/processing/workerProtocol'
import { toSafeWorkerError } from '../../src/domain/safeWorkerError'

export interface InProcessPcapProcessingStats {
  processRequests: number
  buildPlanRequests: number
  terminations: number
}

export function createInProcessPcapProcessingClient(
  stats?: InProcessPcapProcessingStats,
): PcapProcessingWorkerClient {
  const counters = stats ?? { processRequests: 0, buildPlanRequests: 0, terminations: 0 }
  const factory = (): WorkerLike => {
    const listeners = new Set<(ev: MessageEvent) => void>()
    let cachedSession: Awaited<ReturnType<typeof processCapture>> | null = null
    const emit = (response: PcapProcessingWorkerResponse) => {
      for (const listener of listeners) listener({ data: response } as MessageEvent)
    }

    return {
      postMessage(message: unknown) {
        const msg = message as PcapProcessingWorkerRequest
        queueMicrotask(async () => {
          const versionError = validateProcessingProtocolVersion(msg.protocolVersion)
          if (versionError) {
            emit({ type: 'error', requestId: msg.requestId, code: versionError, message: versionError })
            return
          }
          if (msg.type === 'cancel') return

          if (msg.type === 'process') {
            counters.processRequests++
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
              const { wire: container } = containerMetadataFromSessionTransferable(cachedSession)
              emit({
                type: 'discovered',
                requestId: msg.requestId,
                generationId: msg.generationId,
                discovery: discoveryToWire(cachedSession.discovery),
                container,
              })
            } catch (error) {
              const safe = toSafeWorkerError(
                error,
                'pcap-processing',
                PCAP_PROCESSING_WORKER_ERROR.parseFailed,
              )
              emit({
                type: 'error',
                requestId: msg.requestId,
                generationId: msg.generationId,
                code: PCAP_PROCESSING_WORKER_ERROR.parseFailed,
                message: safe.safeMessage,
              })
            }
            return
          }

          if (msg.type === 'build-plan') {
            counters.buildPlanRequests++
            if (!cachedSession || cachedSession.generationId !== msg.generationId) {
              emit({
                type: 'error',
                requestId: msg.requestId,
                generationId: msg.generationId,
                code: PCAP_PROCESSING_WORKER_ERROR.staleGeneration,
                message: 'No session for generation',
              })
              return
            }
            try {
              const plan = buildPlanFromWireSnapshot(cachedSession, msg.snapshot, msg.profile)
              emit({
                type: 'plan-built',
                requestId: msg.requestId,
                generationId: msg.generationId,
                plan: planToWireExport(plan).wire,
              })
            } catch (error) {
              const safe = toSafeWorkerError(
                error,
                'pcap-processing',
                PCAP_PROCESSING_WORKER_ERROR.internal,
              )
              emit({
                type: 'error',
                requestId: msg.requestId,
                generationId: msg.generationId,
                code: safe.code,
                message: safe.safeMessage,
              })
            }
          }
        })
      },
      terminate() {
        cachedSession = null
        counters.terminations++
        listeners.clear()
      },
      addEventListener(_type: 'message', listener: (ev: MessageEvent) => void) {
        listeners.add(listener)
      },
      removeEventListener(_type: 'message', listener: (ev: MessageEvent) => void) {
        listeners.delete(listener)
      },
    }
  }

  return new PcapProcessingWorkerClient(factory)
}
