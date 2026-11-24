/**
 * T05 — compressed input detection and transparent gzip inflate via DecompressionStream.
 * Limits apply to inflated size; never call file.arrayBuffer() (stream only).
 */

import {
  MAX_PCAP_FILE_BYTES,
  MAX_TEXT_FILE_BYTES,
} from '../../domain/capabilityContract.ts'

/** Ceiling while kind is unknown — after inflate, per-kind limits apply again. */
export const MAX_INFLATED_BYTES = Math.max(MAX_TEXT_FILE_BYTES, MAX_PCAP_FILE_BYTES)

/** Inflated:compressed ratio ceiling (gzip bomb) — aligned with archive bomb policy. */
export const MAX_GZIP_INFLATION_RATIO = 100
/** Minimum compressed size before ratio check (avoid tiny false positives). */
export const GZIP_RATIO_CHECK_MIN_COMPRESSED_BYTES = 256

export type CompressedFormat = 'gzip' | 'zip' | 'xz' | 'zstd' | 'bzip2'

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

/** Strip a single trailing `.gz` for pipeline / export names (never trust gzip FNAME). */
export function stripGzipExtension(fileName: string): string {
  const stripped = fileName.replace(/\.gz$/i, '')
  return stripped.length > 0 ? stripped : 'input'
}

export interface DecompressGzipResult {
  readonly file: File
  readonly inflatedBytes: number
  readonly compressedBytes: number
}

/**
 * Stream-inflate a gzip File. Aborts as soon as inflated bytes exceed the limit (gzip bomb).
 * Responds to AbortSignal. Does not recurse into nested compression.
 */
export async function decompressGzipToFile(
  file: File,
  options: {
    readonly signal?: AbortSignal
    readonly maxInflatedBytes?: number
    readonly onProgress?: (inflatedBytes: number) => void
  } = {},
): Promise<DecompressGzipResult> {
  if (typeof DecompressionStream === 'undefined') {
    throw new DecompressError('gzip-unsupported-api')
  }

  const maxInflated = options.maxInflatedBytes ?? MAX_INFLATED_BYTES
  const signal = options.signal
  if (signal?.aborted) throw new DecompressError('cancelled')

  // Bounded header probe (first 10 bytes) — never surface FNAME/comment into errors.
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
        if (signal?.aborted) throw new DecompressError('cancelled')
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

  // Prevent unhandled rejection if we abort early (bomb / cancel) before awaiting pump.
  void pump.catch(() => undefined)

  try {
    for (;;) {
      if (signal?.aborted) throw new DecompressError('cancelled')
      const { done, value } = await reader.read()
      if (done) break
      inflated += value.byteLength
      if (inflated > maxInflated) {
        await settleStreams()
        throw new DecompressError('gzip-bomb')
      }
      const compForRatio = Math.max(compressedSeen, file.size > 0 ? Math.min(file.size, compressedSeen || file.size) : compressedSeen)
      if (
        compForRatio >= GZIP_RATIO_CHECK_MIN_COMPRESSED_BYTES
        && inflated > compForRatio * MAX_GZIP_INFLATION_RATIO
      ) {
        await settleStreams()
        throw new DecompressError('gzip-bomb')
      }
      chunks.push(value)
      options.onProgress?.(inflated)
    }
    await pump
    // Final ratio check against full compressed size (ISIZE is not trusted for prealloc).
    if (
      file.size >= GZIP_RATIO_CHECK_MIN_COMPRESSED_BYTES
      && inflated > file.size * MAX_GZIP_INFLATION_RATIO
    ) {
      throw new DecompressError('gzip-bomb')
    }
  } catch (err) {
    await settleStreams()
    if (err instanceof DecompressError) throw err
    if (signal?.aborted) throw new DecompressError('cancelled')
    throw new DecompressError('gzip-corrupt')
  } finally {
    signal?.removeEventListener('abort', onAbort)
  }

  const name = stripGzipExtension(file.name)
  // Copy into fresh ArrayBuffers so File/BlobPart typing accepts the parts (TS 5.7+).
  const parts: BlobPart[] = chunks.map((c) => {
    const copy = new Uint8Array(c.byteLength)
    copy.set(c)
    return copy
  })
  const out = new File(parts, name, {
    type: 'application/octet-stream',
    lastModified: file.lastModified,
  })
  return {
    file: out,
    inflatedBytes: inflated,
    compressedBytes: file.size,
  }
}
