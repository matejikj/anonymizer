/**
 * Chunked anonymized export coordinator (ARCHITECTURE §7.5 / §3.5 / Krok 9).
 * Uses the same ReplacementPlan as the anonymized viewport.
 */

import { buildLineIndex } from '../../engine/lineIndex.ts'
import { matchesOverlapping } from '../../engine/packedMatchIndex.ts'
import { transformWithPlan } from '../../engine/transform.ts'
import type {
  ExportWorkerRequest,
  ExportWorkerResponse,
  PackedMatchWindow,
} from '../../workers/protocol.ts'
import { EXPORT_PROTOCOL_VERSION, WORKER_ERROR } from '../../workers/protocol.ts'
import { ExportWorkerClient } from '../../app/exportWorkerClient.ts'
import {
  applyPackedLineEndings,
  sliceEndingWindow,
} from './lineEndings.ts'
import {
  buildReplacementSnapshotFromPlan,
  getExportPlanSnapshot,
  type ExportPlanSnapshot,
} from './replacementSnapshot.ts'
import { anonymizedDownloadName } from './exportFileName.ts'
import { getSessionModel } from '../workspace/sessionModel.ts'

/** Target chunk size ~1–2 MiB of original UTF-16 units (ARCHITECTURE §7.5). */
export const EXPORT_CHUNK_CHARS = 1_500_000

export type ExportProgress = {
  phase: 'preparing' | 'transforming' | 'done' | 'cancelled' | 'error'
  processedBytes: number
  totalBytes: number
  message: string
}

export type ExportResult = {
  blob: Blob
  fileName: string
  byteLength: number
  usedWorker: boolean
}

export class ExportCancelledError extends Error {
  constructor() {
    super('Export zrušen')
    this.name = 'ExportCancelledError'
  }
}

function buildMatchWindow(
  snapshot: ExportPlanSnapshot,
  from: number,
  to: number,
): { window: PackedMatchWindow; windowReplacements: string[] } {
  const ids = matchesOverlapping(snapshot.packed, from, to)
  const n = ids.length
  const starts = new Uint32Array(n)
  const lengths = new Uint32Array(n)
  const entityIndexes = new Uint32Array(n)
  const flags = new Uint16Array(n)
  const windowReplacements: string[] = []
  for (let i = 0; i < n; i++) {
    const id = ids[i]!
    starts[i] = snapshot.packed.starts[id]!
    lengths[i] = snapshot.packed.lengths[id]!
    entityIndexes[i] = snapshot.packed.entityIndexes[id]!
    flags[i] = snapshot.packed.flags[id]!
    windowReplacements.push(snapshot.plan.replacements[id] ?? '')
  }
  return {
    window: {
      starts: starts.buffer.slice(starts.byteOffset, starts.byteOffset + starts.byteLength),
      lengths: lengths.buffer.slice(lengths.byteOffset, lengths.byteOffset + lengths.byteLength),
      entityIndexes: entityIndexes.buffer.slice(
        entityIndexes.byteOffset,
        entityIndexes.byteOffset + entityIndexes.byteLength,
      ),
      flags: flags.buffer.slice(flags.byteOffset, flags.byteOffset + flags.byteLength),
      count: n,
      originalFrom: from,
    },
    windowReplacements,
  }
}

/** Split original into [from,to) ranges on physical line boundaries. */
export function planExportChunks(
  original: string,
  maxChars = EXPORT_CHUNK_CHARS,
): Array<{ from: number; to: number; fromLine: number; lineCount: number }> {
  const lineIndex = buildLineIndex(original)
  const chunks: Array<{ from: number; to: number; fromLine: number; lineCount: number }> = []
  let from = 0
  let fromLine = 1
  let line = 1
  while (from < original.length) {
    let to = Math.min(original.length, from + maxChars)
    if (to < original.length) {
      // Snap to end of the physical line containing `to`
      const lineAt = lineIndex.lineAt(Math.max(from, to - 1))
      const range = lineIndex.lineContentRange(lineAt)
      // Include the newline after this line if present
      let end = range.end
      if (end < original.length && original[end] === '\r' && original[end + 1] === '\n') end += 2
      else if (end < original.length && (original[end] === '\n' || original[end] === '\r')) end += 1
      to = Math.max(end, from + 1)
      line = lineAt
    } else {
      line = lineIndex.lineCount
    }
    const lineCount = line - fromLine + 1
    chunks.push({ from, to, fromLine, lineCount })
    from = to
    fromLine = line + 1
  }
  if (chunks.length === 0) {
    chunks.push({ from: 0, to: 0, fromLine: 1, lineCount: 1 })
  }
  return chunks
}

/**
 * Transform one original slice with the shared plan and restore line endings.
 * Used by the main-thread multi-chunk path (tests / Worker-unavailable).
 */
export function transformExportChunk(
  snapshot: ExportPlanSnapshot,
  chunk: { from: number; to: number; fromLine: number; lineCount: number },
): string {
  const slice = snapshot.original.slice(chunk.from, chunk.to)
  const { window, windowReplacements } = buildMatchWindow(snapshot, chunk.from, chunk.to)
  const starts = new Uint32Array(window.starts)
  const lengths = new Uint32Array(window.lengths)
  const parts: string[] = []
  let cursor = 0
  const to = slice.length
  for (let i = 0; i < starts.length; i++) {
    const absStart = starts[i]!
    const absEnd = absStart + lengths[i]!
    const localStart = absStart - window.originalFrom
    const localEnd = absEnd - window.originalFrom
    if (localEnd <= 0 || localStart >= to) continue
    const replacement = windowReplacements[i]
    if (!replacement) continue
    const from = Math.max(0, localStart)
    if (from > cursor) parts.push(slice.slice(cursor, from))
    if (localStart >= 0 && localEnd <= to) parts.push(replacement)
    else parts.push(slice.slice(from, Math.min(to, localEnd)))
    cursor = Math.max(cursor, Math.min(to, localEnd))
  }
  if (cursor < to) parts.push(slice.slice(cursor))
  const lf = parts.join('')
  const endingWindow = sliceEndingWindow(
    snapshot.lineEndings,
    chunk.fromLine,
    chunk.lineCount,
  )
  return applyPackedLineEndings(lf, new Uint8Array(endingWindow.endings))
}

/**
 * Reference full export on the main thread (tests / tiny logs).
 * Byte-identical target for chunked worker path after ending restore.
 */
export function exportAnonymizedReference(snapshot: ExportPlanSnapshot): string {
  const lf = transformWithPlan(snapshot.original, snapshot.packed, snapshot.plan)
  return applyPackedLineEndings(lf, snapshot.lineEndings)
}

/** Assemble anonymized text from planned chunks on the main thread (no full Worker). */
export function exportAnonymizedChunkedMain(
  snapshot: ExportPlanSnapshot,
  maxChars = EXPORT_CHUNK_CHARS,
  signal?: AbortSignal,
): string {
  const chunks = planExportChunks(snapshot.original, maxChars)
  const parts: string[] = []
  for (const chunk of chunks) {
    if (signal?.aborted) throw new ExportCancelledError()
    parts.push(transformExportChunk(snapshot, chunk))
  }
  return parts.join('')
}

export async function runChunkedExport(options: {
  onProgress?: (p: ExportProgress) => void
  signal?: AbortSignal
  /** Force main-thread path (no Worker). */
  forceMainThread?: boolean
  /** Override chunk size (tests / large-log simulation). */
  maxChunkChars?: number
}): Promise<ExportResult> {
  const session = getSessionModel()
  const snapshot = getExportPlanSnapshot(session)
  if (!session || !snapshot) {
    throw new Error('Žádná relace k exportu')
  }
  return runChunkedExportFromSnapshot(snapshot, {
    ...options,
    fileName: anonymizedDownloadName(snapshot.fileName),
  })
}

export async function runChunkedExportFromSnapshot(
  snapshot: ExportPlanSnapshot,
  options: {
    onProgress?: (p: ExportProgress) => void
    signal?: AbortSignal
    forceMainThread?: boolean
    maxChunkChars?: number
    fileName?: string
  },
): Promise<ExportResult> {
  const maxChars = options.maxChunkChars ?? EXPORT_CHUNK_CHARS
  const fileName = options.fileName ?? anonymizedDownloadName(snapshot.fileName)
  const chunks = planExportChunks(snapshot.original, maxChars)
  const totalBytes = snapshot.byteLength
  options.onProgress?.({
    phase: 'preparing',
    processedBytes: 0,
    totalBytes,
    message: 'Připravuji export…',
  })

  if (options.signal?.aborted) throw new ExportCancelledError()

  const useMain =
    options.forceMainThread ||
    (chunks.length <= 1 && snapshot.original.length < maxChars)

  if (useMain) {
    const text =
      chunks.length <= 1
        ? exportAnonymizedReference(snapshot)
        : exportAnonymizedChunkedMain(snapshot, maxChars, options.signal)
    if (options.signal?.aborted) throw new ExportCancelledError()
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
    options.onProgress?.({
      phase: 'done',
      processedBytes: totalBytes,
      totalBytes,
      message: 'Export hotov',
    })
    return { blob, fileName, byteLength: blob.size, usedWorker: false }
  }

  const client = new ExportWorkerClient()
  const requestId = `export-${Date.now().toString(36)}`
  const buffers: ArrayBuffer[] = []
  let settled = false

  try {
    await new Promise<void>((resolve, reject) => {
      const onAbort = () => {
        client.cancel()
        reject(new ExportCancelledError())
      }
      options.signal?.addEventListener('abort', onAbort, { once: true })

      const unsub = client.onMessage((msg: ExportWorkerResponse) => {
        if (msg.requestId !== requestId) return
        if (msg.type === 'chunk-exported') {
          buffers[msg.sequence] = msg.utf8
          const processed = Math.min(
            totalBytes,
            Math.round(((msg.sequence + 1) / chunks.length) * totalBytes),
          )
          options.onProgress?.({
            phase: 'transforming',
            processedBytes: processed,
            totalBytes,
            message: `Transformuji… ${msg.sequence + 1}/${chunks.length}`,
          })
          return
        }
        if (msg.type === 'export-complete') {
          if (settled) return
          settled = true
          options.signal?.removeEventListener('abort', onAbort)
          unsub()
          resolve()
          return
        }
        if (msg.type === 'error') {
          if (settled) return
          settled = true
          options.signal?.removeEventListener('abort', onAbort)
          unsub()
          if (msg.code === WORKER_ERROR.cancelled) reject(new ExportCancelledError())
          else reject(new Error(msg.message))
        }
      })

      client.start(requestId, buildReplacementSnapshotFromPlan(snapshot))

      for (let i = 0; i < chunks.length; i++) {
        if (options.signal?.aborted) {
          client.cancel()
          reject(new ExportCancelledError())
          return
        }
        const chunk = chunks[i]!
        const slice = snapshot.original.slice(chunk.from, chunk.to)
        const { window, windowReplacements } = buildMatchWindow(
          snapshot,
          chunk.from,
          chunk.to,
        )
        const lineEndings = sliceEndingWindow(
          snapshot.lineEndings,
          chunk.fromLine,
          chunk.lineCount,
        )
        const msg: ExportWorkerRequest = {
          type: 'export-chunk',
          protocolVersion: EXPORT_PROTOCOL_VERSION,
          requestId,
          sequence: i,
          text: slice,
          matchWindow: window,
          windowReplacements,
          lineEndings,
          final: i === chunks.length - 1,
        }
        const transfer: Transferable[] = [
          window.starts,
          window.lengths,
          window.entityIndexes,
          window.flags,
          lineEndings.endings,
        ]
        client.postChunk(msg, transfer)
      }
    })
  } finally {
    client.dispose()
  }

  // Worker already restored endings per chunk — concatenate UTF-8 parts without a full string.
  const ordered = chunks.map((_, i) => buffers[i]).filter((b): b is ArrayBuffer => !!b)
  if (ordered.length !== chunks.length) {
    throw new Error('Export Worker nevrátil všechny chunky')
  }
  const blob = new Blob(ordered, { type: 'text/plain;charset=utf-8' })
  options.onProgress?.({
    phase: 'done',
    processedBytes: totalBytes,
    totalBytes,
    message: 'Export hotov',
  })
  return { blob, fileName, byteLength: blob.size, usedWorker: true }
}

export function downloadBlob(fileName: string, blob: Blob): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = fileName
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export type ClipboardCopyResult =
  | { ok: true; method: 'clipboard-item' | 'write-text' }
  | { ok: false; blob: Blob; reason: string }

/**
 * Prefer ClipboardItem(Blob); fall back to writeText after materializing string.
 * On failure, keep the Blob for download (ARCHITECTURE §3.5 / §14).
 * Large-log mode should pass allowStringFallback=false unless the user confirmed.
 */
export async function copyAnonymizedBlob(
  blob: Blob,
  options: { allowStringFallback: boolean } = { allowStringFallback: true },
): Promise<ClipboardCopyResult> {
  try {
    if (typeof ClipboardItem !== 'undefined' && navigator.clipboard?.write) {
      await navigator.clipboard.write([new ClipboardItem({ 'text/plain': blob })])
      return { ok: true, method: 'clipboard-item' }
    }
  } catch {
    // try string fallback
  }
  if (!options.allowStringFallback) {
    return { ok: false, blob, reason: 'clipboard-item-failed' }
  }
  try {
    const text = await blob.text()
    await navigator.clipboard.writeText(text)
    return { ok: true, method: 'write-text' }
  } catch (err) {
    return {
      ok: false,
      blob,
      reason: err instanceof Error ? err.message : 'clipboard-denied',
    }
  }
}
