/// <reference lib="webworker" />
/**
 * Export Web Worker — chunked transform to UTF-8 ArrayBuffers (ARCHITECTURE §8 / Krok 9).
 * Transform must match `transformSlice` / ReplacementPlan used by the anonymized pane.
 * Line endings are restored per chunk so the main thread can Blob-concat without a full string.
 */

import type { ExportWorkerRequest, ExportWorkerResponse } from './protocol.ts'
import {
  validateExportProtocolVersion,
  WORKER_ERROR,
} from './protocol.ts'
import { applyPackedLineEndings } from '../features/export-log/lineEndings.ts'
import { toSafeWorkerError } from '../domain/safeWorkerError.ts'

function rejectExportVersion(msg: ExportWorkerRequest, code: string): void {
  post({
    type: 'error',
    requestId: 'requestId' in msg ? msg.requestId : '',
    code,
    message: 'Neplatná verze export worker protokolu',
  })
}

function assertExportVersion(msg: ExportWorkerRequest): boolean {
  const err = validateExportProtocolVersion(msg.protocolVersion)
  if (err) {
    rejectExportVersion(msg, err)
    return false
  }
  return true
}

let requestId = ''
let totalBytes = 0

function post(msg: ExportWorkerResponse, transfer?: Transferable[]): void {
  if (transfer && transfer.length > 0) {
    ;(self as DedicatedWorkerGlobalScope).postMessage(msg, transfer)
  } else {
    ;(self as DedicatedWorkerGlobalScope).postMessage(msg)
  }
}

/**
 * Same semantics as engine `transformSlice` for a chunk whose absolute offsets
 * are given by matchWindow.starts and originalFrom.
 */
function transformChunk(
  text: string,
  starts: Uint32Array,
  lengths: Uint32Array,
  replacements: string[],
  originalFrom: number,
): string {
  const parts: string[] = []
  let cursor = 0
  const to = text.length
  for (let i = 0; i < starts.length; i++) {
    const absStart = starts[i]!
    const absEnd = absStart + lengths[i]!
    const localStart = absStart - originalFrom
    const localEnd = absEnd - originalFrom
    if (localEnd <= 0 || localStart >= to) continue
    const replacement = replacements[i]
    if (!replacement) continue
    const from = Math.max(0, localStart)
    if (from > cursor) parts.push(text.slice(cursor, from))
    if (localStart >= 0 && localEnd <= to) {
      parts.push(replacement)
    } else {
      parts.push(text.slice(from, Math.min(to, localEnd)))
    }
    cursor = Math.max(cursor, Math.min(to, localEnd))
  }
  if (cursor < to) parts.push(text.slice(cursor))
  return parts.join('')
}

self.onmessage = (ev: MessageEvent<ExportWorkerRequest>) => {
  const msg = ev.data
  try {
    switch (msg.type) {
      case 'start-export': {
        if (!assertExportVersion(msg)) return
        requestId = msg.requestId
        totalBytes = 0
        return
      }
      case 'cancel': {
        if (!assertExportVersion(msg)) return
        if (msg.requestId === requestId) {
          post({
            type: 'error',
            requestId,
            code: WORKER_ERROR.cancelled,
            message: 'Export zrušen',
          })
        }
        return
      }
      case 'export-chunk': {
        if (!assertExportVersion(msg)) return
        if (msg.requestId !== requestId) return
        const { matchWindow, windowReplacements, lineEndings } = msg
        const starts = new Uint32Array(matchWindow.starts)
        const lengths = new Uint32Array(matchWindow.lengths)
        let lfText: string
        try {
          lfText = transformChunk(
            msg.text,
            starts,
            lengths,
            windowReplacements,
            matchWindow.originalFrom,
          )
        } catch {
          // T07: chunk transform failure — length-preserving mask; endings still restored.
          lfText = 'x'.repeat(msg.text.length)
        }
        const endings = new Uint8Array(lineEndings.endings)
        const withEndings = applyPackedLineEndings(lfText, endings)
        const utf8 = new TextEncoder().encode(withEndings)
        const buffer = utf8.buffer.slice(
          utf8.byteOffset,
          utf8.byteOffset + utf8.byteLength,
        )
        totalBytes += utf8.byteLength
        post(
          {
            type: 'chunk-exported',
            requestId,
            sequence: msg.sequence,
            utf8: buffer,
          },
          [buffer],
        )
        if (msg.final) {
          post({ type: 'export-complete', requestId, byteLength: totalBytes })
        }
        return
      }
      default:
        return
    }
  } catch (err) {
    const safe = toSafeWorkerError(err, 'export', WORKER_ERROR.internal)
    post({
      type: 'error',
      requestId: msg.requestId,
      code: WORKER_ERROR.internal,
      message: safe.safeMessage,
    })
  }
}
