/**
 * Incremental Blob chunk feeder — Blob.stream() primary, bounded slice fallback.
 * Never materializes the entire file as one ArrayBuffer.
 */

export interface ChunkFeedOptions {
  chunkSize?: number
  preferStream?: boolean
  signal?: AbortSignal
  onChunk?: (fileOffset: number, length: number) => void
}

const DEFAULT_CHUNK_SIZE = 64 * 1024

export type ChunkCallback = (chunk: Uint8Array, fileOffset: number) => void | Promise<void>

/** Feed a Blob in bounded chunks; invokes callback for each chunk. */
export async function feedBlobChunks(
  blob: Blob,
  onChunk: ChunkCallback,
  options: ChunkFeedOptions = {},
): Promise<void> {
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE
  const preferStream = options.preferStream ?? typeof blob.stream === 'function'
  options.signal?.throwIfAborted()

  if (preferStream && typeof blob.stream === 'function') {
    try {
      await feedViaStream(blob, onChunk, options)
      return
    } catch {
      // fall through to slice windows
    }
  }

  await feedViaSliceWindows(blob, onChunk, chunkSize, options)
}

async function feedViaStream(
  blob: Blob,
  onChunk: ChunkCallback,
  options: ChunkFeedOptions,
): Promise<void> {
  const reader = blob.stream().getReader()
  let fileOffset = 0
  try {
    for (;;) {
      options.signal?.throwIfAborted()
      const { done, value } = await reader.read()
      if (done) break
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value)
      options.onChunk?.(fileOffset, chunk.byteLength)
      await onChunk(chunk, fileOffset)
      fileOffset += chunk.byteLength
    }
  } finally {
    reader.releaseLock()
  }
}

async function feedViaSliceWindows(
  blob: Blob,
  onChunk: ChunkCallback,
  chunkSize: number,
  options: ChunkFeedOptions,
): Promise<void> {
  let fileOffset = 0
  const total = blob.size
  while (fileOffset < total) {
    options.signal?.throwIfAborted()
    const end = Math.min(fileOffset + chunkSize, total)
    const ab = await blob.slice(fileOffset, end).arrayBuffer()
    const chunk = new Uint8Array(ab)
    options.onChunk?.(fileOffset, chunk.byteLength)
    await onChunk(chunk, fileOffset)
    fileOffset = end
  }
}

/** One-shot feeder for sync reference adapter — yields the full buffer as a single chunk. */
export async function feedArrayBuffer(
  buffer: ArrayBuffer,
  onChunk: ChunkCallback,
): Promise<void> {
  await onChunk(new Uint8Array(buffer), 0)
}

/** Reassembly buffer for incremental framing across chunk boundaries. */
export class ReassemblyBuffer {
  private chunks: Uint8Array[] = []
  private totalLength = 0
  private consumed = 0

  append(chunk: Uint8Array, _fileOffset: number): void {
    if (chunk.byteLength === 0) return
    this.chunks.push(chunk)
    this.totalLength += chunk.byteLength
  }

  get available(): number {
    return this.totalLength - this.consumed
  }

  view(): Uint8Array {
    this.compactIfNeeded()
    if (this.chunks.length === 1) return this.chunks[0]!.subarray(this.consumed)
    const out = new Uint8Array(this.available)
    let write = 0
    let skip = this.consumed
    for (const c of this.chunks) {
      if (skip >= c.byteLength) {
        skip -= c.byteLength
        continue
      }
      const take = c.subarray(skip)
      out.set(take, write)
      write += take.byteLength
      skip = 0
    }
    return out
  }

  consume(n: number): void {
    if (n > this.available) {
      throw new Error(`ReassemblyBuffer: consume ${n} but only ${this.available} available`)
    }
    this.consumed += n
    this.compactIfNeeded()
  }

  private compactIfNeeded(): void {
    if (this.consumed < 65536 && this.totalLength < 4 * 1024 * 1024) return
    if (this.consumed === 0) return
    const rest = this.view()
    this.chunks = [rest]
    this.totalLength = rest.byteLength
    this.consumed = 0
  }
}
