/**
 * T44 — bounded raw deflate inflate via Compression Streams (deflate-raw).
 */

import { ARCHIVE_LIMITS } from './limits.ts'

export type InflateRawErrorCode =
  | 'deflate-unsupported-api'
  | 'deflate-corrupt'
  | 'archive-bomb'
  | 'cancelled'

export class InflateRawError extends Error {
  readonly code: InflateRawErrorCode
  constructor(code: InflateRawErrorCode) {
    super(code)
    this.name = 'InflateRawError'
    this.code = code
  }
}

export async function inflateDeflateRaw(
  compressed: Uint8Array,
  options: {
    readonly maxInflatedBytes: number
    readonly compressedBytesForRatio?: number
    readonly signal?: AbortSignal
  },
): Promise<Uint8Array> {
  if (typeof DecompressionStream === 'undefined') {
    throw new InflateRawError('deflate-unsupported-api')
  }
  if (options.signal?.aborted) throw new InflateRawError('cancelled')

  const ds = new DecompressionStream('deflate-raw')
  const writer = ds.writable.getWriter()
  const reader = ds.readable.getReader()
  const chunks: Uint8Array[] = []
  let inflated = 0

  // Copy into a fresh ArrayBuffer-backed view (TS BufferSource / SharedArrayBuffer).
  const input = new Uint8Array(compressed.byteLength)
  input.set(compressed)

  const pump = (async () => {
    try {
      await writer.write(input)
      await writer.close()
    } catch (err) {
      await writer.abort(err).catch(() => undefined)
      throw err
    }
  })()
  void pump.catch(() => undefined)

  try {
    for (;;) {
      if (options.signal?.aborted) throw new InflateRawError('cancelled')
      const { done, value } = await reader.read()
      if (done) break
      inflated += value.byteLength
      if (inflated > options.maxInflatedBytes) {
        await Promise.allSettled([writer.abort(), reader.cancel()])
        throw new InflateRawError('archive-bomb')
      }
      const comp = options.compressedBytesForRatio ?? compressed.byteLength
      if (
        comp >= ARCHIVE_LIMITS.ratioCheckMinCompressedBytes
        && inflated > comp * ARCHIVE_LIMITS.maxInflationRatio
      ) {
        await Promise.allSettled([writer.abort(), reader.cancel()])
        throw new InflateRawError('archive-bomb')
      }
      chunks.push(value)
    }
    await pump
  } catch (err) {
    if (err instanceof InflateRawError) throw err
    if (options.signal?.aborted) throw new InflateRawError('cancelled')
    throw new InflateRawError('deflate-corrupt')
  }

  const out = new Uint8Array(inflated)
  let off = 0
  for (const c of chunks) {
    out.set(c, off)
    off += c.byteLength
  }
  return out
}
