/// <reference lib="webworker" />
/**
 * PCAP export worker — incremental streaming export with backpressure (Stage 11–13).
 * Step 3–4: optional full-literal recovery stream + compact INDEX after anonymized SHA-256 binding.
 */

import type { PcapExportWorkerRequest, PcapExportWorkerResponse } from '../pcap/export/workerProtocol'
import {
  PCAP_EXPORT_WORKER_ERROR,
  validateExportProtocolVersion,
} from '../pcap/export/workerProtocol'
import type { ParseIssue } from '../pcap/domain/types'
import { descriptorsFromWire } from '../pcap/processing/containerWireAdapter'
import { planFromWire } from '../pcap/processing/planWireAdapter'
import { runIncrementalExport } from '../pcap/export/incremental'
import { ExportPlanRejectedError } from '../pcap/export/incremental/planGuard'
import { CancellationError } from '../pcap/capture/cancellation'
import { DualStreamChunkBackpressure } from '../pcap/export/chunkBackpressure'
import { IncrementalSha256, bytesToHex } from '../crypto/incrementalSha256'
import { AnonymizedProvenanceRecorder } from '../pcap/export/anonymizedProvenance'
import { toSafeWorkerError } from '../domain/safeWorkerError'

let activeRequestId = ''
let chunkBackpressure: DualStreamChunkBackpressure | null = null

function post(msg: PcapExportWorkerResponse, transfer?: Transferable[]): void {
  if (transfer && transfer.length > 0) {
    ;(self as DedicatedWorkerGlobalScope).postMessage(msg, transfer)
  } else {
    ;(self as DedicatedWorkerGlobalScope).postMessage(msg)
  }
}

async function handleIncrementalBuild(msg: Extract<PcapExportWorkerRequest, { type: 'build-incremental' }>): Promise<void> {
  activeRequestId = msg.requestId
  const versionErr = validateExportProtocolVersion(msg.protocolVersion)
  if (versionErr) {
    post({ type: 'error', requestId: msg.requestId, code: versionErr, message: 'Invalid export protocol version' })
    return
  }

  const recoveryEnabled = msg.recovery?.enabled === true

  chunkBackpressure = new DualStreamChunkBackpressure()
  const anonHasher = recoveryEnabled ? new IncrementalSha256() : null
  let anonymizedByteLength = 0
  let anonymizedChunkCount = 0

  try {
    const plan = planFromWire(msg.plan, msg.plan.profileId)
    const descriptors = descriptorsFromWire(msg.descriptors)
    const baselineIssues = msg.baselineIssues?.map((i) => ({
      severity: i.severity as ParseIssue['severity'],
      code: i.code,
      message: i.message,
      packetNumber: i.packetNumber,
      fileOffset: i.fileOffset,
    })) ?? []

    const copyAnon = recoveryEnabled && msg.recovery?.copyAnon === true
    const provenance = copyAnon ? new AnonymizedProvenanceRecorder() : undefined

    const result = await runIncrementalExport({
      plan,
      descriptors,
      sourceBlob: msg.sourceBlob,
      expectedGenerationId: msg.expectedGenerationId,
      expectedProfileHash: msg.expectedPolicyHash ?? msg.expectedProfileHash,
      batchLimits: msg.batchLimits,
      baselineIssues,
      provenance,
      isCancelled: () => activeRequestId !== msg.requestId,
      onProgress: (p) => {
        post({
          type: 'progress',
          requestId: msg.requestId,
          phase: p.phase,
          packetsDone: p.packetsDone,
          packetsTotal: p.packetsTotal,
          chunksEmitted: p.chunksEmitted,
          streamId: 'anonymized',
        })
      },
      onChunk: async (buffer, chunkIndex) => {
        if (anonHasher) {
          anonHasher.update(new Uint8Array(buffer))
          anonymizedByteLength += buffer.byteLength
        }
        await chunkBackpressure!.acquire('anonymized')
        if (activeRequestId !== msg.requestId) {
          throw new CancellationError('Export cancelled')
        }
        anonymizedChunkCount += 1
        post(
          {
            type: 'chunk',
            requestId: msg.requestId,
            chunkIndex,
            buffer,
            streamId: 'anonymized',
          },
          [buffer],
        )
      },
    })

    if (activeRequestId !== msg.requestId) {
      post({
        type: 'error',
        requestId: msg.requestId,
        code: PCAP_EXPORT_WORKER_ERROR.cancelled,
        message: 'Export cancelled',
      })
      return
    }

    let recoveryChunkCount = 0
    let anonymizedSha256Hex: string | undefined
    let recoveryCreated = false

    if (recoveryEnabled && anonHasher) {
      const anonymizedSha256 = anonHasher.digest()
      anonymizedSha256Hex = bytesToHex(anonymizedSha256)

      post({
        type: 'progress',
        requestId: msg.requestId,
        phase: 'binding',
        packetsDone: result.changedPackets,
        packetsTotal: plan.packets.length,
        streamId: 'recovery',
      })

      // Dynamic import keeps recovery-off call graph free of the writer module body
      // until recovery is actually requested for this export.
      const { writeFullLiteralRecoveryBundle } = await import(
        '../pcap/recovery/export/recoveryBundleWriter'
      )
      const copies = provenance?.finish(anonymizedByteLength, msg.sourceBlob.size) ?? null

      const recoveryResult = await writeFullLiteralRecoveryBundle({
        sourceBlob: msg.sourceBlob,
        descriptors,
        plan,
        anonymizedSha256,
        anonymizedByteLength,
        indexSeed: msg.recovery?.indexSeed,
        copyAnon: copies != null && copies.length > 0,
        provenanceCopies: copies ?? undefined,
        isCancelled: () => activeRequestId !== msg.requestId,
        onProgress: (p) => {
          post({
            type: 'progress',
            requestId: msg.requestId,
            phase: p.phase,
            packetsDone: p.framesEmitted,
            packetsTotal: Math.max(1, Math.ceil(p.bytesTotal / (1024 * 1024))),
            chunksEmitted: recoveryChunkCount,
            streamId: 'recovery',
            bytesDone: p.bytesDone,
            bytesTotal: p.bytesTotal,
          })
        },
        onChunk: async (buffer, chunkIndex) => {
          await chunkBackpressure!.acquire('recovery')
          if (activeRequestId !== msg.requestId) {
            throw new CancellationError('Export cancelled')
          }
          recoveryChunkCount += 1
          post(
            {
              type: 'chunk',
              requestId: msg.requestId,
              chunkIndex,
              buffer,
              streamId: 'recovery',
            },
            [buffer],
          )
        },
      })

      if (!recoveryResult.ok) {
        post({
          type: 'error',
          requestId: msg.requestId,
          code: recoveryResult.code,
          message: recoveryResult.message,
        })
        activeRequestId = ''
        return
      }
      recoveryCreated = true
    }

    if (activeRequestId !== msg.requestId) {
      post({
        type: 'error',
        requestId: msg.requestId,
        code: PCAP_EXPORT_WORKER_ERROR.cancelled,
        message: 'Export cancelled',
      })
      return
    }

    post({
      type: 'built-incremental',
      requestId: msg.requestId,
      chunkCount: anonymizedChunkCount,
      result: {
        fileName: result.fileName,
        changedPackets: result.changedPackets,
        truncatedPayloads: result.truncatedPayloads,
        validationValid: result.validationValid,
        validationIssueCount: result.validationIssueCount,
        validationNewBlockingCount: result.validation.newBlockingIssues.length,
        checksumCounts: { ...result.checksumReport.counts },
        recoveryCreated,
        recoveryChunkCount: recoveryCreated ? recoveryChunkCount : undefined,
        anonymizedByteLength: recoveryEnabled ? anonymizedByteLength : undefined,
        anonymizedSha256Hex,
      },
    })
    activeRequestId = ''
  } catch (err) {
    if (err instanceof ExportPlanRejectedError) {
      const safe = toSafeWorkerError(err, 'pcap-export', PCAP_EXPORT_WORKER_ERROR.planRejected)
      post({
        type: 'error',
        requestId: msg.requestId,
        code: PCAP_EXPORT_WORKER_ERROR.planRejected,
        message: safe.safeMessage,
      })
    } else if (err instanceof CancellationError) {
      post({
        type: 'error',
        requestId: msg.requestId,
        code: PCAP_EXPORT_WORKER_ERROR.cancelled,
        message: toSafeWorkerError(err, 'pcap-export', 'cancelled').safeMessage,
      })
    } else {
      const safe = toSafeWorkerError(err, 'pcap-export', PCAP_EXPORT_WORKER_ERROR.internal)
      post({
        type: 'error',
        requestId: msg.requestId,
        code: PCAP_EXPORT_WORKER_ERROR.internal,
        message: safe.safeMessage,
      })
    }
    activeRequestId = ''
  } finally {
    chunkBackpressure?.reset()
    chunkBackpressure = null
  }
}

self.onmessage = (ev: MessageEvent<PcapExportWorkerRequest>) => {
  const msg = ev.data
  try {
    switch (msg.type) {
      case 'cancel': {
        const versionErr = validateExportProtocolVersion(msg.protocolVersion)
        if (versionErr) {
          post({ type: 'error', requestId: msg.requestId, code: versionErr, message: 'Invalid protocol version' })
          return
        }
        if (msg.requestId === activeRequestId) activeRequestId = ''
        return
      }
      case 'chunk-ack': {
        const versionErr = validateExportProtocolVersion(msg.protocolVersion)
        if (versionErr) {
          post({ type: 'error', requestId: msg.requestId, code: versionErr, message: 'Invalid protocol version' })
          return
        }
        if (msg.requestId === activeRequestId) {
          chunkBackpressure?.ack(msg.streamId ?? 'anonymized')
        }
        return
      }
      case 'build-incremental': {
        void handleIncrementalBuild(msg)
        return
      }
      default: {
        const unknown = msg as { type: string; requestId?: string }
        post({
          type: 'error',
          requestId: unknown.requestId ?? '',
          code: PCAP_EXPORT_WORKER_ERROR.internal,
          message: `Unknown export worker request: ${unknown.type}`,
        })
        return
      }
    }
  } catch (err) {
    const safe = toSafeWorkerError(err, 'pcap-export', PCAP_EXPORT_WORKER_ERROR.internal)
    post({
      type: 'error',
      requestId: 'requestId' in msg ? msg.requestId : '',
      code: PCAP_EXPORT_WORKER_ERROR.internal,
      message: safe.safeMessage,
    })
    activeRequestId = ''
  }
}
