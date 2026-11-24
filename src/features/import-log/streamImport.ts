/**
 * Dual streaming import: encoding decode + Worker detection via detectFileBytes.
 * ARCHITECTURE §8 / Stage 1 / T43 — worker sees UTF-8 baseline; offsets match CodeMirror LF.
 */

import type { RulesetConfig } from '../../domain/configSchema.ts'
import { createDefaultRulesetConfig } from '../../domain/configSchema.ts'
import { sanitizeStructuredLogText } from '../../engine/structuredLogSanitize.ts'
import { INPUT_LIMITS } from './inputLimits.ts'
import {
  createLineAssembler,
  pushBytes,
  pushText,
  takePackedLineEndings,
  utf8ByteLength,
} from './streamingDecode.ts'
import { createTextDecoder } from './textEncoding.ts'
import { getRecommendedChunkBytes } from './chunkSizing.ts'
import {
  createIdleProgress,
  phaseMessage,
  type ImportProgress,
} from './importProgress.ts'
import {
  DetectionWorkerClient,
  type DetectionResult,
} from '../../app/workerClient.ts'
import { detectFileBytes, detectTextChunks } from './detectCanonical.ts'
import { readFileByteChunks } from './chunking.ts'
import type { TextEncodingLabel } from './textEncoding.ts'
import type { StructuredSanitizeStats } from '../../engine/structuredLogSanitize.ts'

export interface StreamImportHandlers {
  onProgress?: (p: ImportProgress) => void
  /** Append decoded canonical LF text for the editor (main thread). */
  onTextAppend?: (text: string) => void
}

export interface StreamImportResult {
  /** LF-normalized text — same bytes sent to the detection worker. */
  text: string
  lineEndings: Uint8Array
  detection: DetectionResult
  progress: ImportProgress
  elapsedMs: number
  /** T43 */
  sourceEncoding: TextEncodingLabel
  outputEncoding: 'utf-8'
  structuredStats?: StructuredSanitizeStats
}

export class ImportCancelledError extends Error {
  constructor() {
    super('Import zrušen')
    this.name = 'ImportCancelledError'
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new ImportCancelledError()
}

/**
 * Import a File: decode (T43 encoding) → structured sanitize → UTF-8 Blob → detectFileBytes.
 * Non-UTF-8 never hits the UTF-8-only worker; architecture keeps streaming worker detection.
 */
export async function importFileAndDetect(
  file: Blob,
  client: DetectionWorkerClient,
  options: {
    profile?: RulesetConfig
    chunkBytes?: number
    signal?: AbortSignal
    handlers?: StreamImportHandlers
    /** T43 — encoding from preflight (detected or user override). */
    encoding?: TextEncodingLabel
  } = {},
): Promise<StreamImportResult> {
  const t0 = performance.now()
  if (file.size > INPUT_LIMITS.fileMaxBytes) {
    throw new Error(
      `Soubor překračuje limit ${INPUT_LIMITS.fileMaxBytes} bajtů (${file.size}).`,
    )
  }

  const profile = options.profile ?? createDefaultRulesetConfig()
  const chunkBytes = options.chunkBytes ?? getRecommendedChunkBytes()
  const handlers = options.handlers ?? {}
  const encoding: TextEncodingLabel = options.encoding ?? 'utf-8'

  let progress: ImportProgress = {
    ...createIdleProgress(),
    phase: 'checking',
    message: phaseMessage('checking'),
    totalBytes: file.size,
  }
  handlers.onProgress?.(progress)

  progress = {
    ...progress,
    phase: 'loading',
    message: phaseMessage('loading'),
  }
  handlers.onProgress?.(progress)

  // Decode source encoding → JS string with original newlines (not editor lfParts).
  const decoder = createTextDecoder(encoding, { fatal: false })
  const decodedParts: string[] = []
  let sourceBytes = 0
  let provisionalLines = 0
  for await (const chunk of readFileByteChunks(file, chunkBytes)) {
    throwIfAborted(options.signal)
    const view = new Uint8Array(chunk.bytes, chunk.byteOffset, chunk.byteLength)
    decodedParts.push(decoder.decode(view, { stream: !chunk.final }))
    sourceBytes += view.byteLength
    // Cheap line estimate for limit (exact count comes from UTF-8 pass).
    provisionalLines += view.reduce((n, b) => n + (b === 0x0a ? 1 : 0), 0)
    progress = {
      ...progress,
      phase: 'loading',
      message: phaseMessage('loading'),
      processedBytes: sourceBytes,
      processedLines: provisionalLines,
    }
    handlers.onProgress?.(progress)
    if (provisionalLines > INPUT_LIMITS.fileMaxLines) {
      throw new Error(`Překročen limit ${INPUT_LIMITS.fileMaxLines} řádků.`)
    }
  }
  decodedParts.push(decoder.decode())

  const structured = sanitizeStructuredLogText(decodedParts.join(''))
  const utf8Blob = new Blob([new TextEncoder().encode(structured.text)], {
    type: 'text/plain;charset=utf-8',
  })

  const assembler = createLineAssembler('utf-8')
  const lfParts: string[] = []
  let processedBytes = 0

  const detection = await detectFileBytes(client, utf8Blob, {
    profile,
    chunkBytes,
    signal: options.signal,
    onFirstPassChunk: (view, final) => {
      const { lfFragment } = pushBytes(assembler, view, final)
      if (lfFragment.length > 0) {
        lfParts.push(lfFragment)
        handlers.onTextAppend?.(lfFragment)
      }
      processedBytes += view.byteLength
      progress = {
        ...progress,
        phase: 'loading',
        message: phaseMessage('loading'),
        processedBytes,
        processedLines: assembler.processedLines,
      }
      handlers.onProgress?.(progress)
      if (assembler.processedLines > INPUT_LIMITS.fileMaxLines) {
        client.cancel()
        throw new Error(`Překročen limit ${INPUT_LIMITS.fileMaxLines} řádků.`)
      }
    },
    onProgress: (ev) => {
      if (processedBytes >= utf8Blob.size) {
        progress = {
          ...progress,
          phase: 'analyzing',
          message: phaseMessage('analyzing'),
          requestId: ev.requestId,
          processedBytes: Math.max(processedBytes, ev.processedBytes),
          processedLines: ev.processedLines,
        }
        handlers.onProgress?.(progress)
      }
    },
  })

  const text = lfParts.join('')
  const lineEndings = takePackedLineEndings(assembler)

  progress = {
    ...progress,
    phase: 'done',
    message: phaseMessage('done'),
    requestId: detection.requestId,
    processedBytes,
    processedLines: detection.lineCount,
    failedRuleIds: detection.failedRuleIds,
  }
  handlers.onProgress?.(progress)

  return {
    text,
    lineEndings,
    detection,
    progress,
    elapsedMs: performance.now() - t0,
    sourceEncoding: encoding,
    outputEncoding: 'utf-8',
    structuredStats: structured.stats,
  }
}

/**
 * Import paste text: normalize to canonical LF, detect via worker.
 */
export async function importPasteAndDetect(
  rawText: string,
  client: DetectionWorkerClient,
  options: {
    profile?: RulesetConfig
    chunkBytes?: number
    signal?: AbortSignal
    handlers?: StreamImportHandlers
  } = {},
): Promise<StreamImportResult> {
  const t0 = performance.now()
  const byteLen = utf8ByteLength(rawText)
  if (byteLen > INPUT_LIMITS.pasteMaxBytes) {
    throw new Error(
      `Vložený text překračuje limit ${INPUT_LIMITS.pasteMaxBytes} bajtů (${byteLen}).`,
    )
  }

  const profile = options.profile ?? createDefaultRulesetConfig()
  const chunkBytes = options.chunkBytes ?? getRecommendedChunkBytes()
  const handlers = options.handlers ?? {}

  let progress: ImportProgress = {
    ...createIdleProgress(),
    phase: 'checking',
    message: phaseMessage('checking'),
    totalBytes: byteLen,
  }
  handlers.onProgress?.(progress)

  progress = {
    ...progress,
    phase: 'loading',
    message: phaseMessage('loading'),
  }
  handlers.onProgress?.(progress)

  const structured = sanitizeStructuredLogText(rawText)
  const assembler = createLineAssembler('utf-8')
  const lfParts: string[] = []
  let processedBytes = 0
  const detection = await detectTextChunks(client, structured.text, {
    profile,
    chunkBytes,
    signal: options.signal,
    onFirstPassChunk: (slice, final) => {
      throwIfAborted(options.signal)
      const { lfFragment } = pushText(assembler, slice, final)
      if (lfFragment.length > 0) {
        lfParts.push(lfFragment)
        handlers.onTextAppend?.(lfFragment)
      }
      processedBytes += utf8ByteLength(slice)
      progress = {
        ...progress,
        phase: 'loading',
        message: phaseMessage('loading'),
        processedBytes,
        processedLines: assembler.processedLines,
      }
      handlers.onProgress?.(progress)
      if (assembler.processedLines > INPUT_LIMITS.fileMaxLines) {
        client.cancel()
        throw new Error(`Překročen limit ${INPUT_LIMITS.fileMaxLines} řádků.`)
      }
    },
    onProgress: (ev) => {
      if (processedBytes >= byteLen) {
        progress = {
          ...progress,
          phase: 'analyzing',
          message: phaseMessage('analyzing'),
          requestId: ev.requestId,
          processedBytes,
          processedLines: ev.processedLines,
        }
        handlers.onProgress?.(progress)
      }
    },
  })

  const text = lfParts.join('')
  const lineEndings = takePackedLineEndings(assembler)

  progress = {
    ...progress,
    phase: 'done',
    message: phaseMessage('done'),
    requestId: detection.requestId,
    processedBytes,
    processedLines: detection.lineCount,
    failedRuleIds: detection.failedRuleIds,
  }
  handlers.onProgress?.(progress)

  return {
    text,
    lineEndings,
    detection,
    progress,
    elapsedMs: performance.now() - t0,
    sourceEncoding: 'utf-8',
    outputEncoding: 'utf-8',
    structuredStats: structured.stats,
  }
}
