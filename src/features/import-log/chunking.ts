/**
 * File / paste chunking with surrogate-pair safety (ARCHITECTURE §8).
 */

import { BYTES_PER_MIB } from './inputLimits.ts'
import { utf8ByteLength } from './streamingDecode.ts'

export const CHUNK_SIZE = {
  minBytes: 512 * 1024,
  defaultBytes: 1 * BYTES_PER_MIB,
  maxBytes: 4 * BYTES_PER_MIB,
} as const

export interface ByteChunk {
  bytes: ArrayBuffer
  byteOffset: number
  byteLength: number
  sequence: number
  final: boolean
}

export interface TextChunk {
  text: string
  sequence: number
  utf8Bytes: number
  final: boolean
}

/** Split an ArrayBuffer into transferable-sized views (copies into new buffers). */
export function splitArrayBuffer(
  source: ArrayBuffer,
  chunkBytes: number,
): ByteChunk[] {
  const size = Math.max(CHUNK_SIZE.minBytes, Math.min(CHUNK_SIZE.maxBytes, chunkBytes))
  const out: ByteChunk[] = []
  let offset = 0
  let sequence = 0
  while (offset < source.byteLength) {
    const len = Math.min(size, source.byteLength - offset)
    const slice = source.slice(offset, offset + len)
    offset += len
    out.push({
      bytes: slice,
      byteOffset: 0,
      byteLength: slice.byteLength,
      sequence: sequence++,
      final: offset >= source.byteLength,
    })
  }
  if (out.length === 0) {
    out.push({
      bytes: new ArrayBuffer(0),
      byteOffset: 0,
      byteLength: 0,
      sequence: 0,
      final: true,
    })
  } else {
    out[out.length - 1]!.final = true
  }
  return out
}

/**
 * Split a paste string into slices that do not break UTF-16 surrogate pairs.
 * Targets ~chunkBytes of UTF-8 payload per slice.
 */
export function* iterateTextChunks(text: string, chunkBytes: number): Generator<TextChunk> {
  const target = Math.max(CHUNK_SIZE.minBytes, Math.min(CHUNK_SIZE.maxBytes, chunkBytes))
  if (text.length === 0) {
    yield { text: '', sequence: 0, utf8Bytes: 0, final: true }
    return
  }

  let start = 0
  let sequence = 0
  while (start < text.length) {
    let end = start
    let bytes = 0
    // Byte-count via UTF-16 code-unit arithmetic, not per-character TextEncoder calls —
    // encoding one character at a time here made this O(n) with a huge constant factor
    // (millions of encoder allocations for a large paste), freezing the main thread.
    while (end < text.length && bytes < target) {
      const code = text.charCodeAt(end)!
      if (code >= 0xd800 && code <= 0xdbff && end + 1 < text.length) {
        // surrogate pair — always takes both code units, 4 UTF-8 bytes (supplementary plane)
        bytes += 4
        end += 2
      } else if (code < 0x80) {
        bytes += 1
        end += 1
      } else if (code < 0x800) {
        bytes += 2
        end += 1
      } else {
        bytes += 3
        end += 1
      }
    }
    // If we stopped mid-pair (shouldn't), extend
    if (end < text.length) {
      const prev = text.charCodeAt(end - 1)
      if (prev >= 0xd800 && prev <= 0xdbff) end++
    }
    const slice = text.slice(start, end)
    start = end
    yield {
      text: slice,
      sequence: sequence++,
      utf8Bytes: utf8ByteLength(slice),
      final: start >= text.length,
    }
  }
}

/** Materialized compatibility helper for callers that explicitly need random access. */
export function splitPasteText(text: string, chunkBytes: number): TextChunk[] {
  return [...iterateTextChunks(text, chunkBytes)]
}

/** Read a Blob/File into sequential ArrayBuffer chunks via stream. */
export async function* readFileByteChunks(
  file: Blob,
  chunkBytes: number,
): AsyncGenerator<ByteChunk> {
  const size = Math.max(CHUNK_SIZE.minBytes, Math.min(CHUNK_SIZE.maxBytes, chunkBytes))
  if (typeof file.stream === 'function') {
    const reader = file.stream().getReader()
    let sequence = 0
    let pending = new Uint8Array(0)
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (!value || value.byteLength === 0) continue
      const merged = new Uint8Array(pending.byteLength + value.byteLength)
      merged.set(pending, 0)
      merged.set(value, pending.byteLength)
      pending = merged
      while (pending.byteLength >= size) {
        const piece = pending.slice(0, size)
        pending = pending.slice(size)
        yield {
          bytes: piece.buffer,
          byteOffset: piece.byteOffset,
          byteLength: piece.byteLength,
          sequence: sequence++,
          final: false,
        }
      }
    }
    yield {
      bytes: pending.buffer.slice(
        pending.byteOffset,
        pending.byteOffset + pending.byteLength,
      ),
      byteOffset: 0,
      byteLength: pending.byteLength,
      sequence: sequence++,
      final: true,
    }
    return
  }

  // Bounded fallback for runtimes without Blob.stream(); never materialize the whole file.
  let offset = 0
  let sequence = 0
  while (offset < file.size) {
    const end = Math.min(file.size, offset + size)
    const bytes = await file.slice(offset, end).arrayBuffer()
    offset = end
    yield {
      bytes,
      byteOffset: 0,
      byteLength: bytes.byteLength,
      sequence: sequence++,
      final: offset >= file.size,
    }
  }
  if (file.size === 0) {
    yield {
      bytes: new ArrayBuffer(0),
      byteOffset: 0,
      byteLength: 0,
      sequence: 0,
      final: true,
    }
  }
}
