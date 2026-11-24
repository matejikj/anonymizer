/**
 * Bounded sequential reader of original capture bytes for full-literal recovery.
 * Aligns plaintext frames to packet record/block boundaries when they fit the
 * frame budget; oversized records are split safely.
 *
 * Never materializes the entire Blob as one ArrayBuffer.
 */

import type { PacketRecordDescriptor } from '../../domain/types'
import { feedBlobChunks } from '../../capture/chunkFeeder'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import { IncrementalSha256 } from '../../../crypto/incrementalSha256'
import { CancellationError } from '../../capture/cancellation'

export interface SourceRecordSpan {
  readonly start: number
  readonly end: number
}

/** One plaintext piece ready to encrypt as (part of) a DATA frame. */
export interface SourceLiteralPiece {
  /** Absolute file offset of the first byte in `bytes`. */
  readonly fileOffset: number
  readonly bytes: Uint8Array
  /** True when this piece is a split of a single oversized record/span. */
  readonly split: boolean
}

export interface SourceFrameReaderResult {
  readonly originalSha256: Uint8Array
  readonly originalByteLength: number
  readonly pieceCount: number
  /** Spans derived from descriptors (header gap + each record). */
  readonly spans: readonly SourceRecordSpan[]
  /**
   * Maps each emitted piece to its covering source span and DATA-local index.
   * Used later by INDEX range directory (step 4); step 3 keeps it for tests.
   */
  readonly rangeDirectory: readonly SourceRangeEntry[]
}

export interface SourceRangeEntry {
  readonly spanStart: number
  readonly spanEnd: number
  readonly fileOffset: number
  readonly length: number
  readonly dataFrameLocalIndex: number
  readonly split: boolean
}

/**
 * Build contiguous spans covering [0, blobSize).
 * Cut points: 0, each descriptor.fileOffset (sorted unique), blobSize.
 */
export function buildSourceRecordSpans(
  blobSize: number,
  descriptors: readonly PacketRecordDescriptor[],
): SourceRecordSpan[] {
  if (blobSize < 0 || !Number.isFinite(blobSize)) {
    return []
  }
  const cuts = new Set<number>([0, blobSize])
  for (const d of descriptors) {
    if (Number.isFinite(d.fileOffset) && d.fileOffset > 0 && d.fileOffset < blobSize) {
      cuts.add(d.fileOffset >>> 0)
    }
  }
  const ordered = [...cuts].sort((a, b) => a - b)
  const spans: SourceRecordSpan[] = []
  for (let i = 0; i < ordered.length - 1; i++) {
    const start = ordered[i]!
    const end = ordered[i + 1]!
    if (end > start) spans.push({ start, end })
  }
  return spans
}

/**
 * Pack spans into frame-sized pieces. Prefer whole spans per frame; split when
 * a span exceeds maxPlaintextBytes.
 */
export function planLiteralPieces(
  spans: readonly SourceRecordSpan[],
  maxPlaintextBytes: number = PCAP_RECOVERY_LIMITS.defaultFramePlaintextBytes,
): Array<{ fileOffset: number; length: number; split: boolean }> {
  const max = Math.min(maxPlaintextBytes, PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes)
  const pieces: Array<{ fileOffset: number; length: number; split: boolean }> = []
  let pendingStart = -1
  let pendingEnd = -1

  const flushPending = () => {
    if (pendingStart < 0) return
    pieces.push({
      fileOffset: pendingStart,
      length: pendingEnd - pendingStart,
      split: false,
    })
    pendingStart = -1
    pendingEnd = -1
  }

  for (const span of spans) {
    const spanLen = span.end - span.start
    if (spanLen > max) {
      flushPending()
      let offset = span.start
      while (offset < span.end) {
        const length = Math.min(max, span.end - offset)
        pieces.push({ fileOffset: offset, length, split: true })
        offset += length
      }
      continue
    }
    if (pendingStart < 0) {
      pendingStart = span.start
      pendingEnd = span.end
      continue
    }
    if (pendingEnd - pendingStart + spanLen <= max && span.start === pendingEnd) {
      pendingEnd = span.end
      continue
    }
    flushPending()
    pendingStart = span.start
    pendingEnd = span.end
  }
  flushPending()
  return pieces
}

export async function readSourceLiteralPieces(input: {
  sourceBlob: Blob
  descriptors: readonly PacketRecordDescriptor[]
  maxPlaintextBytes?: number
  isCancelled?: () => boolean
  onPiece: (piece: SourceLiteralPiece) => void | Promise<void>
  /** Read window for Blob.slice fallback path (also used when assembling pieces). */
  readChunkSize?: number
}): Promise<PcapRecoveryResult<SourceFrameReaderResult>> {
  const blobSize = input.sourceBlob.size
  if (blobSize > PCAP_RECOVERY_LIMITS.maxBundleImportBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'source exceeds recovery import limit')
  }
  const spans = buildSourceRecordSpans(blobSize, input.descriptors)
  const planned = planLiteralPieces(spans, input.maxPlaintextBytes)
  if (planned.length > PCAP_RECOVERY_LIMITS.maxDataFrames) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many DATA frames')
  }

  const hasher = new IncrementalSha256()
  const rangeDirectory: SourceRangeEntry[] = []
  let pieceCount = 0
  let planIndex = 0
  let assembleOffset = 0
  let assembleBuf: Uint8Array | null = null
  let assembleWritten = 0

  const startAssemble = (length: number) => {
    assembleBuf = new Uint8Array(length)
    assembleWritten = 0
  }

  const finishPiece = async (fileOffset: number, split: boolean) => {
    if (!assembleBuf || assembleWritten !== assembleBuf.byteLength) {
      throw new Error('source frame assemble underflow')
    }
    const bytes = assembleBuf
    assembleBuf = null
    hasher.update(bytes)
    const covering = spans.find((s) => fileOffset >= s.start && fileOffset < s.end) ?? {
      start: fileOffset,
      end: fileOffset + bytes.byteLength,
    }
    rangeDirectory.push({
      spanStart: covering.start,
      spanEnd: covering.end,
      fileOffset,
      length: bytes.byteLength,
      dataFrameLocalIndex: pieceCount,
      split,
    })
    pieceCount += 1
    await input.onPiece({ fileOffset, bytes, split })
  }

  await feedBlobChunks(
    input.sourceBlob,
    async (chunk, fileOffset) => {
      if (input.isCancelled?.()) {
        throw new CancellationError('Recovery source read cancelled')
      }
      let chunkPos = 0
      while (chunkPos < chunk.byteLength && planIndex < planned.length) {
        const plan = planned[planIndex]!
        if (assembleBuf === null) {
          // Skip forward until we reach this piece's file offset.
          const absolute = fileOffset + chunkPos
          if (absolute < plan.fileOffset) {
            const skip = Math.min(chunk.byteLength - chunkPos, plan.fileOffset - absolute)
            chunkPos += skip
            continue
          }
          startAssemble(plan.length)
          assembleOffset = plan.fileOffset
        }
        const need = assembleBuf!.byteLength - assembleWritten
        const take = Math.min(need, chunk.byteLength - chunkPos)
        assembleBuf!.set(chunk.subarray(chunkPos, chunkPos + take), assembleWritten)
        assembleWritten += take
        chunkPos += take
        if (assembleWritten === assembleBuf!.byteLength) {
          await finishPiece(assembleOffset, plan.split)
          planIndex += 1
        }
      }
    },
    {
      chunkSize: input.readChunkSize ?? 64 * 1024,
      preferStream: true,
    },
  )

  if (planIndex !== planned.length || assembleBuf !== null) {
    return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'source stream ended before planned frames')
  }

  return recoveryOk({
    originalSha256: hasher.digest(),
    originalByteLength: blobSize,
    pieceCount,
    spans,
    rangeDirectory,
  })
}
