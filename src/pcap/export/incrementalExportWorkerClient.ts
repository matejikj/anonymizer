/**
 * Incremental PCAP export worker client (Stage 11–12).
 * ACK/backpressure (max 2 in-flight chunks), no sync buildCaptureFromPlan fallback.
 */

import type { PacketRecordDescriptor } from '../domain/types'
import type { PcapPlanSnapshot } from './planSnapshot'
import { descriptorsToWire } from '../processing/containerWireAdapter'
import { packPlanPatches } from '../processing/planWireAdapter'
import type {
  PcapExportWorkerRequest,
  PcapExportWorkerResponse,
  WirePlanSnapshot,
} from './workerProtocol'
import {
  PCAP_EXPORT_PROTOCOL_VERSION,
  PCAP_EXPORT_WORKER_ERROR,
  validateExportProtocolVersion,
} from './workerProtocol'
import { CancellationError } from '../capture/cancellation'
import { emptyChecksumCounts, emptyOriginalStateCounts } from '../checksums/types'
import type { IncrementalExportInput, IncrementalExportResult } from './incremental'
import { ExportPlanRejectedError } from './incremental/planGuard'
import type { ExportValidationOutcome } from './incremental/baselineCompare'
import { getPcapExportWorker, disposePcapExportWorker } from './pcapExportWorkerClient'
import type { WireExportBuildResult } from './workerProtocol'
import type { ParseIssue } from '../domain/types'

function tsToWire(ts: PcapPlanSnapshot['packets'][number]['originalTimestamp']) {
  return {
    ticks: ts.ticks.toString(),
    unitsPerSecond: ts.unitsPerSecond.toString(),
    offsetSeconds: ts.offsetSeconds.toString(),
  }
}

function validationFromWire(
  result: WireExportBuildResult,
  baselineIssues: readonly ParseIssue[],
): ExportValidationOutcome {
  const preservedBaselineIssues = baselineIssues.filter((i) => i.severity >= 0)
  const newBlockingCount = result.validationNewBlockingCount ?? 0
  return {
    valid: result.validationValid,
    exportValidation: {
      valid: result.validationValid,
      packetCount: 0,
      issues: [],
    },
    exportIssues: [],
    newBlockingIssues: newBlockingCount > 0
      ? [{ severity: 1, code: 'val-new-blocking', message: `${newBlockingCount} new blocking issue(s)` }]
      : [],
    preservedBaselineIssues,
    validationValid: result.validationValid,
    validationIssueCount: result.validationIssueCount,
  }
}
function planToWire(plan: PcapPlanSnapshot): { wire: WirePlanSnapshot; transfers: ArrayBuffer[] } {
  const { perPacketPatches, patchData } = packPlanPatches(plan.packets)
  const packets = plan.packets.map((p, i) => {
    return {
      index: p.index,
      packetNumber: p.packetNumber,
      drop: p.drop,
      patches: perPacketPatches[i]!,
      truncatedLength: p.truncatedLength,
      originalCapturedLength: p.originalCapturedLength,
      originalLength: p.originalLength,
      linkType: p.linkType,
      interfaceId: p.interfaceId,
      sectionIndex: p.sectionIndex,
      originalTimestamp: tsToWire(p.originalTimestamp),
      dispositionReason: p.dispositionReason,
      changeCounts: p.changeCounts,
      maskedByteCount: p.maskedByteCount,
      primaryProtocol: p.primaryProtocol,
    }
  })
  return {
    wire: {
      generationId: plan.generationId,
      profileId: plan.profileId,
      profileHash: plan.profileHash,
      format: plan.format,
      fileName: plan.fileName,
      engineVersion: plan.engineVersion,
      packets,
      patchData,
      droppedPacketNumbers: [...plan.droppedPacketNumbers],
      timestamps: plan.timestamps,
      timestampAnchorSeed: plan.timestampAnchorSeed,
      changeCategoryTotals: plan.changeCategoryTotals,
      maskedByteCount: plan.maskedByteCount,
      dropsByReason: plan.dropsByReason,
      dropsByProtocol: plan.dropsByProtocol,
      incidents: plan.incidents ?? {
        incidents: [],
        aggregates: [],
        truncated: false,
        totalFailures: 0,
      },
      dispositionLedger: plan.dispositionLedger,
      classicHeader: plan.classicHeader
        ? {
            format: plan.classicHeader.format,
            endian: plan.classicHeader.endian,
            timestampResolution: plan.classicHeader.timestampResolution,
            versionMajor: plan.classicHeader.versionMajor,
            versionMinor: plan.classicHeader.versionMinor,
            snapLen: plan.classicHeader.snapLen,
            linkType: plan.classicHeader.linkType,
            tzOffset: plan.classicHeader.tzOffset,
            sigfigs: plan.classicHeader.sigfigs,
          }
        : undefined,
      pcapngSections: plan.pcapngSections
        ? (plan.pcapngSections as unknown as WirePlanSnapshot['pcapngSections'])
        : undefined,
      pcapngInterfaces: plan.pcapngInterfaces
        ? (plan.pcapngInterfaces as unknown as WirePlanSnapshot['pcapngInterfaces'])
        : undefined,
    },
    transfers: [patchData],
  }
}

export async function buildIncrementalExportViaWorker(
  input: IncrementalExportInput,
): Promise<IncrementalExportResult> {
  if (typeof Worker === 'undefined') {
    throw new Error('Incremental export worker unavailable in this environment')
  }

  const requestId = input.plan.generationId
  const { wire: wirePlan, transfers: planTransfers } = planToWire(input.plan)
  const wireDescriptors = descriptorsToWire(input.descriptors as PacketRecordDescriptor[])

  return new Promise((resolve, reject) => {
    let settled = false
    const w = getPcapExportWorker()
    const chunks: ArrayBuffer[] = []
    const pendingChunks = new Map<number, Promise<void>>()

    const finish = (fn: () => void) => {
      if (settled) return
      settled = true
      cleanup()
      fn()
    }

    const sendAck = (chunkIndex: number, streamId?: 'anonymized' | 'recovery') => {
      if (settled) return
      w.postMessage({
        type: 'chunk-ack',
        protocolVersion: PCAP_EXPORT_PROTOCOL_VERSION,
        requestId,
        chunkIndex,
        streamId,
      } satisfies PcapExportWorkerRequest)
    }

    const handleChunk = async (msg: Extract<PcapExportWorkerResponse, { type: 'chunk' }>) => {
      if (settled || msg.requestId !== requestId) return

      if (input.isCancelled?.()) {
        finish(() => {
          w.postMessage({ type: 'cancel', protocolVersion: PCAP_EXPORT_PROTOCOL_VERSION, requestId } satisfies PcapExportWorkerRequest)
          reject(new CancellationError('Incremental export cancelled'))
        })
        return
      }

      try {
        const streamId = msg.streamId ?? 'anonymized'
        let deliverOk = true
        if (streamId === 'recovery') {
          if (input.deliverRecoveryChunk) {
            deliverOk = await input.deliverRecoveryChunk(msg.buffer, msg.chunkIndex)
          } else {
            const result = input.onRecoveryChunk?.(msg.buffer, msg.chunkIndex)
            if (result instanceof Promise) await result
          }
        } else if (input.deliverChunk) {
          deliverOk = await input.deliverChunk(msg.buffer, msg.chunkIndex)
        } else {
          chunks[msg.chunkIndex] = msg.buffer
          const result = input.onChunk?.(msg.buffer, msg.chunkIndex)
          if (result instanceof Promise) await result
        }

        if (settled || input.isCancelled?.() || !deliverOk) return

        sendAck(msg.chunkIndex, streamId)
      } catch (err) {
        finish(() => reject(err instanceof Error ? err : new Error(String(err))))
      }
    }

    const onMessage = (ev: MessageEvent<PcapExportWorkerResponse>) => {
      const msg = ev.data
      if (msg.requestId !== requestId) return

      if (msg.type === 'progress') {
        if (input.isCancelled?.()) {
          finish(() => {
            w.postMessage({ type: 'cancel', protocolVersion: PCAP_EXPORT_PROTOCOL_VERSION, requestId } satisfies PcapExportWorkerRequest)
            reject(new CancellationError('Incremental export cancelled'))
          })
          return
        }
        input.onProgress?.({
          phase: msg.phase,
          packetsDone: msg.packetsDone,
          packetsTotal: msg.packetsTotal,
          chunksEmitted: msg.chunksEmitted ?? chunks.length,
        })
        return
      }

      if (msg.type === 'chunk') {
        const task = handleChunk(msg)
        pendingChunks.set(msg.chunkIndex, task)
        void task.finally(() => {
          pendingChunks.delete(msg.chunkIndex)
        })
        return
      }

      if (msg.type === 'built-incremental') {
        void Promise.all([...pendingChunks.values()]).then(() => {
          finish(() =>
            resolve({
              chunks,
              fileName: msg.result.fileName,
              changedPackets: msg.result.changedPackets,
              truncatedPayloads: msg.result.truncatedPayloads,
              checksumReport: {
                fields: [],
                counts: msg.result.checksumCounts ?? emptyChecksumCounts(),
                originalStateCounts: emptyOriginalStateCounts(),
              },
              validationValid: msg.result.validationValid,
              validationIssueCount: msg.result.validationIssueCount,
              validation: validationFromWire(msg.result, input.baselineIssues ?? []),
              recoveryCreated: msg.result.recoveryCreated === true,
            }),
          )
        })
        return
      }

      if (msg.type === 'error') {
        finish(() => {
          if (msg.code === PCAP_EXPORT_WORKER_ERROR.cancelled) {
            reject(new CancellationError('Incremental export cancelled'))
          } else if (msg.code === PCAP_EXPORT_WORKER_ERROR.planRejected) {
            reject(new ExportPlanRejectedError(msg.message))
          } else {
            reject(new Error(msg.message))
          }
        })
      }
    }

    const onError = (err: ErrorEvent) => {
      finish(() => {
        disposePcapExportWorker()
        reject(err.error ?? new Error(err.message || 'Incremental export worker failed'))
      })
    }

    const cleanup = () => {
      w.removeEventListener('message', onMessage)
      w.removeEventListener('error', onError)
    }

    w.addEventListener('message', onMessage)
    w.addEventListener('error', onError)

    const req: PcapExportWorkerRequest = {
      type: 'build-incremental',
      protocolVersion: PCAP_EXPORT_PROTOCOL_VERSION,
      requestId,
      plan: wirePlan,
      descriptors: wireDescriptors,
      sourceBlob: input.sourceBlob,
      expectedGenerationId: input.expectedGenerationId,
      expectedProfileHash: input.expectedProfileHash,
      batchLimits: input.batchLimits,
      baselineIssues: input.baselineIssues?.map((i) => ({
        severity: i.severity,
        code: i.code,
        message: i.message,
        packetNumber: i.packetNumber,
        fileOffset: i.fileOffset,
      })),
      recovery: input.recovery?.enabled
        ? {
            enabled: true,
            ...(input.recovery.indexSeed ? { indexSeed: input.recovery.indexSeed } : {}),
            ...(input.recovery.copyAnon === true ? { copyAnon: true } : {}),
          }
        : undefined,
    }
    w.postMessage(req, planTransfers)
  })
}

export { validateExportProtocolVersion }
