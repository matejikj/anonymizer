/**
 * T05 / T72 — compressed input detection and inflate (gzip native + xz/zstd/bzip2 offline).
 * Limits apply to inflated size; gzip uses stream APIs; others use bundled decoders (no CDN).
 */

import { decompress as decompressBz2 } from 'bz2'
import { Decompress as ZstdStreamDecompress, decompress as decompressZstdBuffer } from 'fzstd'
import * as xzNamespace from 'xz-decompress'
import {
  MAX_PCAP_FILE_BYTES,
  MAX_TEXT_FILE_BYTES,
} from '../../domain/capabilityContract.ts'

type XzStreamCtor = new (compressedStream: ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>

/** Ceiling while kind is unknown — after inflate, per-kind limits apply again. */
export const MAX_INFLATED_BYTES = Math.max(MAX_TEXT_FILE_BYTES, MAX_PCAP_FILE_BYTES)

/** Inflated:compressed ratio ceiling (gzip bomb) — aligned with archive bomb policy. */
export const MAX_GZIP_INFLATION_RATIO = 100
/** Minimum compressed size before ratio check (avoid tiny false positives). */
export const GZIP_RATIO_CHECK_MIN_COMPRESSED_BYTES = 256

/** T72 — nested compression / archive layers (gz in tar in zip …). */
export const MAX_COMPRESSION_NEST_DEPTH = 4

export type CompressedFormat = 'gzip' | 'zip' | 'xz' | 'zstd' | 'bzip2'

/** Single-stream inflate formats (ZIP is container, not handled here). */
export type InflateFormat = 'gzip' | 'xz' | 'zstd' | 'bzip2'

export type DecompressErrorCode =
  | 'gzip-bomb'
  | 'gzip-corrupt'
  | 'gzip-unsupported-api'
  | 'gzip-header-invalid'
  | 'cancelled'
  | 'nested-compression'

export class DecompressError extends Error {
  readonly code: DecompressErrorCode

  constructor(code: DecompressErrorCode) {
    super(code)
    this.name = 'DecompressError'
    this.code = code
  }
}

/** CJS/ESM interop for xz-decompress (bundled WASM as data URI, no CDN). */
function resolveXzReadableStream(): XzStreamCtor {
  const root = xzNamespace as Record<string, unknown>
  const candidates: unknown[] = [
    root.XzReadableStream,
    (root.default as { XzReadableStream?: unknown } | undefined)?.XzReadableStream,
    (root['xz-decompress'] as { XzReadableStream?: unknown } | undefined)?.XzReadableStream,
  ]
  for (const c of candidates) {
    if (typeof c === 'function') return c as XzStreamCtor
  }
  throw new DecompressError('gzip-unsupported-api')
}

export function isInflateFormat(format: CompressedFormat): format is InflateFormat {
  return format === 'gzip' || format === 'xz' || format === 'zstd' || format === 'bzip2'
}

/**
 * RFC 1952 §2.3.1 — CM must be 8 (deflate); reserved FLG bits 5–7 must be zero.
 * FNAME/FCOMMENT/mtime are private metadata and must never be copied into errors.
 */
export function validateGzipHeader(head: Uint8Array): 'ok' | 'gzip-header-invalid' {
  if (head.byteLength < 10) return 'gzip-header-invalid'
  if (head[0] !== 0x1f || head[1] !== 0x8b) return 'gzip-header-invalid'
  if (head[2] !== 8) return 'gzip-header-invalid' // CM = deflate
  const flg = head[3] ?? 0
  if ((flg & 0xe0) !== 0) return 'gzip-header-invalid' // reserved bits
  return 'ok'
}

/**
 * Content-based compression magic (RFC / format signatures). Extension is ignored.
 */
export function detectCompressedFormat(head: Uint8Array): CompressedFormat | null {
  if (head.byteLength >= 2 && head[0] === 0x1f && head[1] === 0x8b) return 'gzip'
  if (
    head.byteLength >= 4
    && head[0] === 0x50
    && head[1] === 0x4b
    && head[2] === 0x03
    && head[3] === 0x04
  ) {
    return 'zip'
  }
  if (
    head.byteLength >= 6
    && head[0] === 0xfd
    && head[1] === 0x37
    && head[2] === 0x7a
    && head[3] === 0x58
    && head[4] === 0x5a
    && head[5] === 0x00
  ) {
    return 'xz'
  }
  if (
    head.byteLength >= 4
    && head[0] === 0x28
    && head[1] === 0xb5
    && head[2] === 0x2f
    && head[3] === 0xfd
  ) {
    return 'zstd'
  }
  if (head.byteLength >= 3 && head[0] === 0x42 && head[1] === 0x5a && head[2] === 0x68) {
    return 'bzip2'
  }
  return null
}

/** Strip a single trailing compression extension for pipeline / export names. */
export function stripCompressionExtension(fileName: string, format?: InflateFormat): string {
  const patterns: RegExp[] =
    format === 'gzip'
      ? [/\.gz$/i]
      : format === 'xz'
        ? [/\.xz$/i, /\.lzma$/i]
        : format === 'zstd'
          ? [/\.zst$/i, /\.zstd$/i]
          : format === 'bzip2'
            ? [/\.bz2$/i, /\.bzip2$/i]
            : [/\.gz$/i, /\.xz$/i, /\.lzma$/i, /\.zst$/i, /\.zstd$/i, /\.bz2$/i, /\.bzip2$/i]
  let stripped = fileName
  for (const re of patterns) {
    const next = stripped.replace(re, '')
    if (next !== stripped) {
      stripped = next
      break
    }
  }
  return stripped.length > 0 ? stripped : 'input'
}

/** @deprecated Prefer stripCompressionExtension — kept for T05 call sites. */
export function stripGzipExtension(fileName: string): string {
  return stripCompressionExtension(fileName, 'gzip')
}

export interface DecompressResult {
  readonly file: File
  readonly inflatedBytes: number
  readonly compressedBytes: number
  readonly format: InflateFormat
}

/** @deprecated Alias of DecompressResult (T05 name). */
export type DecompressGzipResult = DecompressResult

function assertNotAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DecompressError('cancelled')
}

function checkInflationBudget(
  inflated: number,
  compressedBytes: number,
  maxInflated: number,
): void {
  if (inflated > maxInflated) throw new DecompressError('gzip-bomb')
  if (
    compressedBytes >= GZIP_RATIO_CHECK_MIN_COMPRESSED_BYTES
    && inflated > compressedBytes * MAX_GZIP_INFLATION_RATIO
  ) {
    throw new DecompressError('gzip-bomb')
  }
}

function fileFromChunks(
  chunks: readonly Uint8Array[],
  name: string,
  lastModified: number,
): File {
  const parts: BlobPart[] = chunks.map((c) => {
    const copy = new Uint8Array(c.byteLength)
    copy.set(c)
    return copy
  })
  return new File(parts, name, {
    type: 'application/octet-stream',
    lastModified,
  })
}

async function collectStreamWithBudget(
  stream: ReadableStream<Uint8Array>,
  options: {
    readonly signal?: AbortSignal
    readonly maxInflatedBytes: number
    readonly compressedBytes: number
    readonly onProgress?: (inflatedBytes: number) => void
  },
): Promise<{ chunks: Uint8Array[]; inflated: number }> {
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let inflated = 0
  const onAbort = (): void => {
    void reader.cancel().catch(() => undefined)
  }
  options.signal?.addEventListener('abort', onAbort, { once: true })
  try {
    for (;;) {
      assertNotAborted(options.signal)
      const { done, value } = await reader.read()
      if (done) break
      inflated += value.byteLength
      checkInflationBudget(inflated, options.compressedBytes, options.maxInflatedBytes)
      chunks.push(value)
      options.onProgress?.(inflated)
    }
  } catch (err) {
    await reader.cancel().catch(() => undefined)
    if (err instanceof DecompressError) throw err
    if (options.signal?.aborted) throw new DecompressError('cancelled')
    throw new DecompressError('gzip-corrupt')
  } finally {
    options.signal?.removeEventListener('abort', onAbort)
  }
  return { chunks, inflated }
}

/**
 * Stream-inflate a gzip File. Aborts as soon as inflated bytes exceed the limit (gzip bomb).
 */
export async function decompressGzipToFile(
  file: File,
  options: {
    readonly signal?: AbortSignal
    readonly maxInflatedBytes?: number
    readonly onProgress?: (inflatedBytes: number) => void
  } = {},
): Promise<DecompressResult> {
  if (typeof DecompressionStream === 'undefined') {
    throw new DecompressError('gzip-unsupported-api')
  }

  const maxInflated = options.maxInflatedBytes ?? MAX_INFLATED_BYTES
  const signal = options.signal
  assertNotAborted(signal)

  try {
    const headBuf = new Uint8Array(await file.slice(0, 16).arrayBuffer())
    if (validateGzipHeader(headBuf) !== 'ok') {
      throw new DecompressError('gzip-header-invalid')
    }
  } catch (err) {
    if (err instanceof DecompressError) throw err
    throw new DecompressError('gzip-corrupt')
  }

  const ds = new DecompressionStream('gzip')
  const writer = ds.writable.getWriter()
  const reader = ds.readable.getReader()
  const chunks: Uint8Array[] = []
  let inflated = 0
  let compressedSeen = 0
  let settled = false

  const settleStreams = async (): Promise<void> => {
    if (settled) return
    settled = true
    await Promise.allSettled([
      writer.abort().catch(() => undefined),
      reader.cancel().catch(() => undefined),
    ])
  }

  const onAbort = (): void => {
    void settleStreams()
  }
  signal?.addEventListener('abort', onAbort, { once: true })

  const pump = (async (): Promise<void> => {
    const src = file.stream().getReader()
    try {
      for (;;) {
        assertNotAborted(signal)
        const { done, value } = await src.read()
        if (done) break
        compressedSeen += value.byteLength
        await writer.write(value)
      }
      await writer.close()
    } catch (err) {
      await writer.abort(err).catch(() => undefined)
      throw err
    } finally {
      src.releaseLock()
    }
  })()

  void pump.catch(() => undefined)

  try {
    for (;;) {
      assertNotAborted(signal)
      const { done, value } = await reader.read()
      if (done) break
      inflated += value.byteLength
      const compForRatio = Math.max(
        compressedSeen,
        file.size > 0 ? Math.min(file.size, compressedSeen || file.size) : compressedSeen,
      )
      checkInflationBudget(inflated, compForRatio, maxInflated)
      chunks.push(value)
      options.onProgress?.(inflated)
    }
    await pump
    checkInflationBudget(inflated, file.size, maxInflated)
  } catch (err) {
    await settleStreams()
    if (err instanceof DecompressError) throw err
    if (signal?.aborted) throw new DecompressError('cancelled')
    throw new DecompressError('gzip-corrupt')
  } finally {
    signal?.removeEventListener('abort', onAbort)
  }

  return {
    file: fileFromChunks(chunks, stripCompressionExtension(file.name, 'gzip'), file.lastModified),
    inflatedBytes: inflated,
    compressedBytes: file.size,
    format: 'gzip',
  }
}

async function decompressXzToFile(
  file: File,
  options: {
    readonly signal?: AbortSignal
    readonly maxInflatedBytes: number
    readonly onProgress?: (inflatedBytes: number) => void
  },
): Promise<DecompressResult> {
  assertNotAborted(options.signal)
  try {
    const XzReadableStream = resolveXzReadableStream()
    const xzStream = new XzReadableStream(file.stream())
    const { chunks, inflated } = await collectStreamWithBudget(xzStream, {
      signal: options.signal,
      maxInflatedBytes: options.maxInflatedBytes,
      compressedBytes: file.size,
      onProgress: options.onProgress,
    })
    return {
      file: fileFromChunks(chunks, stripCompressionExtension(file.name, 'xz'), file.lastModified),
      inflatedBytes: inflated,
      compressedBytes: file.size,
      format: 'xz',
    }
  } catch (err) {
    if (err instanceof DecompressError) throw err
    if (options.signal?.aborted) throw new DecompressError('cancelled')
    throw new DecompressError('gzip-corrupt')
  }
}

async function decompressZstdToFile(
  file: File,
  options: {
    readonly signal?: AbortSignal
    readonly maxInflatedBytes: number
    readonly onProgress?: (inflatedBytes: number) => void
  },
): Promise<DecompressResult> {
  assertNotAborted(options.signal)
  const chunks: Uint8Array[] = []
  let inflated = 0
  try {
    const input = new Uint8Array(await file.arrayBuffer())
    assertNotAborted(options.signal)
    // Prefer streaming so bomb limits abort before full frame allocation when possible.
    const stream = new ZstdStreamDecompress((data) => {
      inflated += data.byteLength
      checkInflationBudget(inflated, file.size, options.maxInflatedBytes)
      chunks.push(data)
      options.onProgress?.(inflated)
    })
    const step = 256 * 1024
    for (let offset = 0; offset < input.byteLength; offset += step) {
      assertNotAborted(options.signal)
      const end = Math.min(offset + step, input.byteLength)
      stream.push(input.subarray(offset, end), end >= input.byteLength)
    }
    if (chunks.length === 0) {
      // Empty / single-shot fallback
      const out = decompressZstdBuffer(input)
      checkInflationBudget(out.byteLength, file.size, options.maxInflatedBytes)
      chunks.push(out)
      inflated = out.byteLength
      options.onProgress?.(inflated)
    }
  } catch (err) {
    if (err instanceof DecompressError) throw err
    if (options.signal?.aborted) throw new DecompressError('cancelled')
    throw new DecompressError('gzip-corrupt')
  }
  return {
    file: fileFromChunks(chunks, stripCompressionExtension(file.name, 'zstd'), file.lastModified),
    inflatedBytes: inflated,
    compressedBytes: file.size,
    format: 'zstd',
  }
}

async function decompressBzip2ToFile(
  file: File,
  options: {
    readonly signal?: AbortSignal
    readonly maxInflatedBytes: number
    readonly onProgress?: (inflatedBytes: number) => void
  },
): Promise<DecompressResult> {
  assertNotAborted(options.signal)
  try {
    const input = new Uint8Array(await file.arrayBuffer())
    assertNotAborted(options.signal)
    // Pure-JS decoder (MIT); CRC off — we already bound size after inflate.
    const out = decompressBz2(input, false)
    checkInflationBudget(out.byteLength, file.size, options.maxInflatedBytes)
    options.onProgress?.(out.byteLength)
    return {
      file: fileFromChunks([out], stripCompressionExtension(file.name, 'bzip2'), file.lastModified),
      inflatedBytes: out.byteLength,
      compressedBytes: file.size,
      format: 'bzip2',
    }
  } catch (err) {
    if (err instanceof DecompressError) throw err
    if (options.signal?.aborted) throw new DecompressError('cancelled')
    throw new DecompressError('gzip-corrupt')
  }
}

/**
 * Inflate a single-stream compressed File (gzip / xz / zstd / bzip2).
 * Does not recurse into nested compression — caller controls nest depth (T72).
 */
export async function decompressToFile(
  file: File,
  format: InflateFormat,
  options: {
    readonly signal?: AbortSignal
    readonly maxInflatedBytes?: number
    readonly onProgress?: (inflatedBytes: number) => void
  } = {},
): Promise<DecompressResult> {
  const maxInflated = options.maxInflatedBytes ?? MAX_INFLATED_BYTES
  switch (format) {
    case 'gzip':
      return decompressGzipToFile(file, { ...options, maxInflatedBytes: maxInflated })
    case 'xz':
      return decompressXzToFile(file, { ...options, maxInflatedBytes: maxInflated })
    case 'zstd':
      return decompressZstdToFile(file, { ...options, maxInflatedBytes: maxInflated })
    case 'bzip2':
      return decompressBzip2ToFile(file, { ...options, maxInflatedBytes: maxInflated })
  }
}

/** Inflate bytes in memory (archive member); same bomb budgets as File path. */
export async function decompressBytes(
  data: Uint8Array,
  format: InflateFormat,
  options: {
    readonly signal?: AbortSignal
    readonly maxInflatedBytes?: number
    readonly nameHint?: string
  } = {},
): Promise<{ data: Uint8Array; inflatedBytes: number; format: InflateFormat }> {
  const name = options.nameHint ?? `member.${format}`
  const copy = new Uint8Array(data.byteLength)
  copy.set(data)
  const file = new File([copy], name, { type: 'application/octet-stream' })
  const out = await decompressToFile(file, format, {
    signal: options.signal,
    maxInflatedBytes: options.maxInflatedBytes,
  })
  return {
    data: new Uint8Array(await out.file.arrayBuffer()),
    inflatedBytes: out.inflatedBytes,
    format: out.format,
  }
}
