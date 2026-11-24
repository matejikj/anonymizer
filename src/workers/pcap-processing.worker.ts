/**
 * PCAP processing worker (Stage 8) — parse, analyze, discover, plan build.
 */

import {
  PCAP_PROCESSING_WORKER_ERROR,
  validateProcessingProtocolVersion,
  type PcapProcessingWorkerRequest,
  type PcapProcessingWorkerResponse,
} from '../pcap/processing/workerProtocol'
import {
  buildPlanFromWireSnapshot,
  containerMetadataFromSessionTransferable,
  discoveryToWire,
  processCapture,
  type ProcessingSession,
} from '../pcap/processing/processingPipeline'
import { planToWireExport } from '../pcap/processing/planWireAdapter'
import type { PcapProfile } from '../pcap/profile/schema'
import { toSafeWorkerError } from '../domain/safeWorkerError'

let activeGeneration: string | null = null
let cancelledGeneration: string | null = null
let session: ProcessingSession | null = null

function post(response: PcapProcessingWorkerResponse, transfer?: Transferable[]): void {
  if (transfer && transfer.length > 0) self.postMessage(response, transfer)
  else self.postMessage(response)
}

function onError(requestId: string, generationId: string | undefined, code: string, message: string): void {
  post({ type: 'error', requestId, generationId, code, message })
}

self.addEventListener('message', (ev: MessageEvent<PcapProcessingWorkerRequest>) => {
  const msg = ev.data
  if (!msg || typeof msg !== 'object' || !('type' in msg)) return

  const versionErr = validateProcessingProtocolVersion(msg.protocolVersion)
  if (versionErr) {
    onError('requestId' in msg ? msg.requestId : 'unknown', undefined, versionErr, 'Invalid protocol version')
    return
  }

  if (msg.type === 'cancel') {
    cancelledGeneration = msg.generationId
    post({
      type: 'progress',
      requestId: msg.requestId,
      generationId: msg.generationId,
      phase: 'discovering',
      packetsDone: 0,
      packetsTotal: 0,
    })
    return
  }

  if (msg.type === 'process') {
    void handleProcess(msg)
    return
  }

  if (msg.type === 'build-plan') {
    void handleBuildPlan(msg)
  }
})

async function handleProcess(msg: Extract<PcapProcessingWorkerRequest, { type: 'process' }>): Promise<void> {
  activeGeneration = msg.generationId
  cancelledGeneration = null
  session = null

  try {
    const result = await processCapture({
      blob: msg.blob,
      fileName: 'capture.pcap',
      format: msg.format,
      policy: msg.policy,
      generationId: msg.generationId,
      sourceId: msg.sourceId,
      batchSize: msg.batchSize,
      isCancelled: () => cancelledGeneration === msg.generationId,
      onProgress: (phase, done, total) => {
        post({
          type: 'progress',
          requestId: msg.requestId,
          generationId: msg.generationId,
          phase: phase === 'parsing' ? 'parsing' : phase === 'analyzing' ? 'analyzing' : 'discovering',
          packetsDone: done,
          packetsTotal: total,
        })
      },
    })

    if (cancelledGeneration === msg.generationId || activeGeneration !== msg.generationId) {
      onError(msg.requestId, msg.generationId, PCAP_PROCESSING_WORKER_ERROR.cancelled, 'Processing cancelled')
      return
    }

    session = result
    const { wire: container, transfers } = containerMetadataFromSessionTransferable(result)
    post(
      {
        type: 'discovered',
        requestId: msg.requestId,
        generationId: msg.generationId,
        discovery: discoveryToWire(result.discovery),
        container,
      },
      transfers,
    )
  } catch (err) {
    const safe = toSafeWorkerError(err, 'pcap-processing', PCAP_PROCESSING_WORKER_ERROR.parseFailed)
    const code = safe.code === 'cancelled'
      ? PCAP_PROCESSING_WORKER_ERROR.cancelled
      : PCAP_PROCESSING_WORKER_ERROR.parseFailed
    onError(msg.requestId, msg.generationId, code, safe.safeMessage)
  }
}

async function handleBuildPlan(msg: Extract<PcapProcessingWorkerRequest, { type: 'build-plan' }>): Promise<void> {
  if (!session || session.generationId !== msg.generationId) {
    onError(msg.requestId, msg.generationId, PCAP_PROCESSING_WORKER_ERROR.staleGeneration, 'No session for generation')
    return
  }

  if (cancelledGeneration === msg.generationId) {
    onError(msg.requestId, msg.generationId, PCAP_PROCESSING_WORKER_ERROR.cancelled, 'Plan build cancelled')
    return
  }

  try {
    post({
      type: 'progress',
      requestId: msg.requestId,
      generationId: msg.generationId,
      phase: 'plan-build',
      packetsDone: 0,
      packetsTotal: session.descriptors.length,
    })

    const profile = msg.profile as PcapProfile
    const plan = buildPlanFromWireSnapshot(
      session,
      msg.snapshot,
      profile,
      (done, total) => {
        post({
          type: 'progress',
          requestId: msg.requestId,
          generationId: msg.generationId,
          phase: 'plan-build',
          packetsDone: done,
          packetsTotal: total,
        })
      },
      { unresolvedClosureFailures: msg.unresolvedClosureFailures },
    )
    // PF-02: transfer patch bytes by ownership instead of structured-cloning them — the plan
    // can hold millions of small patches, and planToWireExport consolidates them into one
    // shared buffer (see packPlanPatches) so the transfer list stays tiny regardless of patch
    // count, instead of one ArrayBuffer (and one transfer-list entry) per patch.
    const { wire, transfers } = planToWireExport(plan)

    post(
      {
        type: 'plan-built',
        requestId: msg.requestId,
        generationId: msg.generationId,
        plan: wire,
      },
      transfers,
    )
  } catch (err) {
    const safe = toSafeWorkerError(err, 'pcap-processing', PCAP_PROCESSING_WORKER_ERROR.internal)
    onError(msg.requestId, msg.generationId, safe.code, safe.safeMessage)
  }
}

export {}
