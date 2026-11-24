/// <reference lib="webworker" />
/**
 * Detection Web Worker — streaming input, line-tail only, packed match index out.
 * ARCHITECTURE §8 / Krok 3.
 */

import type { DetectionWorkerRequest, DetectionWorkerResponse } from './protocol.ts'
import {
  validateDetectionProtocolVersion,
  WORKER_ERROR,
} from './protocol.ts'
import { DetectionSession } from './detectionSession.ts'
import { toSafeWorkerError } from '../domain/safeWorkerError.ts'

function rejectVersion(msg: DetectionWorkerRequest, code: string): void {
  post({
    type: 'error',
    requestId: 'requestId' in msg ? msg.requestId : '',
    code,
    message: 'Neplatná verze worker protokolu',
  })
}

function assertDetectionVersion(msg: DetectionWorkerRequest): boolean {
  const err = validateDetectionProtocolVersion(msg.protocolVersion)
  if (err) {
    rejectVersion(msg, err)
    return false
  }
  return true
}

const session = new DetectionSession({
  onProgress(processedBytes, processedLines) {
    post({
      type: 'progress',
      requestId: session.requestId,
      processedBytes,
      processedLines,
    })
  },
  onRuleStarted(ruleId) {
    post({ type: 'rule-started', requestId: session.requestId, ruleId })
  },
  onHeartbeat(ruleId) {
    post({ type: 'heartbeat', requestId: session.requestId, ruleId })
  },
})

function post(msg: DetectionWorkerResponse, transfer?: Transferable[]): void {
  if (transfer && transfer.length > 0) {
    ;(self as DedicatedWorkerGlobalScope).postMessage(msg, transfer)
  } else {
    ;(self as DedicatedWorkerGlobalScope).postMessage(msg)
  }
}

self.onmessage = (ev: MessageEvent<DetectionWorkerRequest>) => {
  const msg = ev.data
  try {
    switch (msg.type) {
      case 'start-detection': {
        if (!assertDetectionVersion(msg)) return
        session.start(msg.requestId, msg.profile)
        return
      }
      case 'cancel': {
        if (!assertDetectionVersion(msg)) return
        if (msg.requestId === session.requestId) {
          post({
            type: 'error',
            requestId: msg.requestId,
            code: WORKER_ERROR.cancelled,
            message: 'Zrušeno',
          })
        }
        return
      }
      case 'input-chunk': {
        if (!assertDetectionVersion(msg)) return
        if (msg.requestId !== session.requestId) return
        if (msg.bytes != null) {
          const offset = msg.byteOffset ?? 0
          const length = msg.byteLength ?? msg.bytes.byteLength
          if (offset < 0 || length < 0 || offset + length > msg.bytes.byteLength) {
            post({
              type: 'error',
              requestId: msg.requestId,
              code: WORKER_ERROR.invalidChunk,
              message: 'Neplatný byteOffset/byteLength',
            })
            return
          }
          session.pushByteChunk(msg.bytes, offset, length, msg.final)
        } else if (msg.text != null) {
          session.pushTextChunk(msg.text, msg.final)
        } else {
          post({
            type: 'error',
            requestId: msg.requestId,
            code: WORKER_ERROR.invalidChunk,
            message: 'Chunk bez bytes i text',
          })
          return
        }
        post({
          type: 'chunk-accepted',
          requestId: msg.requestId,
          sequence: msg.sequence,
        })
        if (msg.final) {
          const result = session.finalizeDetection()
          post(
            {
              type: 'detected',
              requestId: msg.requestId,
              packedMatches: result.packedMatches,
              entities: result.entities,
              lineCount: result.lineCount,
              incidents: result.incidents,
            },
            result.transfer,
          )
        }
        return
      }
      case 'build-plan': {
        if (!assertDetectionVersion(msg)) return
        if (msg.requestId !== session.requestId) return
        const result = session.buildPlan(msg.entityBitset)
        post(
          {
            type: 'plan-built',
            requestId: msg.requestId,
            planBuffers: result.planBuffers,
          },
          result.transfer,
        )
        return
      }
      case 'sync-replacements': {
        if (!assertDetectionVersion(msg)) return
        if (msg.requestId !== session.requestId) return
        session.applyReplacements(msg.replacements)
        post({ type: 'replacements-synced', requestId: msg.requestId })
        return
      }
      default:
        return
    }
  } catch (err) {
    const code =
      err && typeof err === 'object' && 'code' in err
        ? String((err as { code: string }).code)
        : WORKER_ERROR.internal
    const safe = toSafeWorkerError(err, 'detection', code)
    post({
      type: 'error',
      requestId: msg.requestId,
      code: safe.code,
      message: safe.safeMessage,
    })
  }
}
