/**
 * Plan COPY_ANON + LITERAL restore ops from verified provenance copies.
 * Any invalid copy list → caller must fall back to full-literal.
 */

import type { PacketRecordDescriptor } from '../../domain/types'
import type { ProvenanceCopyRun } from '../../export/anonymizedProvenance'
import { validateProvenanceCopies } from '../../export/anonymizedProvenance'
import { IncrementalSha256 } from '../../../crypto/incrementalSha256'
import { wipeBytes } from '../../../crypto/wipe'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import {
  encodedRestoreFrameSize,
  encodedRestoreOpSize,
  writeRestoreOpsFrame,
  type RestoreOp,
  type RestoreOpPlan,
} from '../codec/literalFrameCodec'
import { RECOVERY_RESTORE_OPS_FRAME_HEADER_BYTES } from '../codec/formatConstants'
import { CancellationError } from '../../capture/cancellation'
import {
  buildSourceRecordSpans,
  type SourceFrameReaderResult,
  type SourceRangeEntry,
} from './sourceFrameReader'

export interface PackedRestoreFrame {
  readonly ops: readonly RestoreOpPlan[]
  readonly originalStart: number
  readonly originalEnd: number
  readonly split: boolean
}

export function planRestoreOps(
  originalByteLength: number,
  copies: readonly ProvenanceCopyRun[],
  anonymizedByteLength: number,
): PcapRecoveryResult<RestoreOpPlan[]> {
  if (!validateProvenanceCopies(copies, originalByteLength, anonymizedByteLength)) {
    return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'invalid COPY_ANON provenance')
  }
  const ops: RestoreOpPlan[] = []
  let cursor = 0
  for (const run of copies) {
    if (run.originalOffset > cursor) {
      ops.push({
        type: 'literal',
        originalOffset: cursor,
        length: run.originalOffset - cursor,
      })
    }
    ops.push({
      type: 'copy-anon',
      originalOffset: run.originalOffset,
      length: run.length,
      anonymizedOffset: run.anonymizedOffset,
    })
    cursor = run.originalOffset + run.length
  }
  if (cursor < originalByteLength) {
    ops.push({
      type: 'literal',
      originalOffset: cursor,
      length: originalByteLength - cursor,
    })
  }
  if (cursor > originalByteLength) {
    return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'COPY_ANON past original end')
  }
  return recoveryOk(ops)
}

export function totalCopyAnonBytes(ops: readonly RestoreOpPlan[]): number {
  let n = 0
  for (const op of ops) {
    if (op.type === 'copy-anon') n += op.length
  }
  return n
}

export function packRestoreOps(
  ops: readonly RestoreOpPlan[],
  maxPlaintextBytes: number = PCAP_RECOVERY_LIMITS.defaultFramePlaintextBytes,
): PcapRecoveryResult<PackedRestoreFrame[]> {
  const max = Math.min(maxPlaintextBytes, PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes)
  const frames: PackedRestoreFrame[] = []
  let current: RestoreOpPlan[] = []

  const flush = (split: boolean) => {
    if (current.length === 0) return
    const first = current[0]!
    const last = current[current.length - 1]!
    frames.push({
      ops: current,
      originalStart: first.originalOffset,
      originalEnd: last.originalOffset + last.length,
      split,
    })
    current = []
  }

  const fits = (op: RestoreOpPlan): boolean => {
    const next = current.concat(op)
    return encodedRestoreFrameSize(next) <= max
  }

  for (const op of ops) {
    if (encodedRestoreOpSize(op) + RECOVERY_RESTORE_OPS_FRAME_HEADER_BYTES > max) {
      if (op.type !== 'literal') {
        return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'COPY_ANON op exceeds frame budget')
      }
      flush(false)
      let offset = op.originalOffset
      let remaining = op.length
      const payloadBudget = max - RECOVERY_RESTORE_OPS_FRAME_HEADER_BYTES - 9
      if (payloadBudget < 1) {
        return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'frame budget too small for LITERAL')
      }
      while (remaining > 0) {
        const length = Math.min(remaining, payloadBudget)
        current = [{ type: 'literal', originalOffset: offset, length }]
        flush(true)
        offset += length
        remaining -= length
      }
      continue
    }
    if (current.length > 0 && !fits(op)) {
      flush(false)
    }
    current.push(op)
  }
  flush(false)

  if (frames.length > PCAP_RECOVERY_LIMITS.maxDataFrames) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many DATA frames')
  }
  return recoveryOk(frames)
}

async function readSourceRange(
  blob: Blob,
  offset: number,
  length: number,
): Promise<PcapRecoveryResult<Uint8Array>> {
  if (length < 0 || offset < 0 || offset + length > blob.size) {
    return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'literal source range invalid')
  }
  if (length === 0) return recoveryOk(new Uint8Array(0))
  const ab = await blob.slice(offset, offset + length).arrayBuffer()
  return recoveryOk(new Uint8Array(ab))
}

export async function emitCopyAnonDataFrames(input: {
  sourceBlob: Blob
  descriptors: readonly PacketRecordDescriptor[]
  copies: readonly ProvenanceCopyRun[]
  anonymizedByteLength: number
  maxPlaintextBytes?: number
  isCancelled?: () => boolean
  onFrame: (frame: {
    plaintext: Uint8Array
    fileOffset: number
    length: number
    split: boolean
  }) => void | Promise<void>
}): Promise<PcapRecoveryResult<SourceFrameReaderResult>> {
  const blobSize = input.sourceBlob.size
  if (blobSize > PCAP_RECOVERY_LIMITS.maxBundleImportBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'source exceeds recovery import limit')
  }
  const planned = planRestoreOps(blobSize, input.copies, input.anonymizedByteLength)
  if (!planned.ok) return planned
  if (totalCopyAnonBytes(planned.value) <= 0) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'COPY_ANON has no copy runs')
  }
  const packed = packRestoreOps(planned.value, input.maxPlaintextBytes)
  if (!packed.ok) return packed

  const spans = buildSourceRecordSpans(blobSize, input.descriptors)
  const hasher = new IncrementalSha256()
  const rangeDirectory: SourceRangeEntry[] = []
  let pieceCount = 0

  for (const frame of packed.value) {
    if (input.isCancelled?.()) {
      throw new CancellationError('Recovery source read cancelled')
    }
    const filled: RestoreOp[] = []
    for (const op of frame.ops) {
      const src = await readSourceRange(input.sourceBlob, op.originalOffset, op.length)
      if (!src.ok) return src
      hasher.update(src.value)
      if (op.type === 'literal') {
        filled.push({
          type: 'literal',
          originalOffset: op.originalOffset,
          length: op.length,
          bytes: src.value,
        })
      } else {
        wipeBytes(src.value)
        filled.push({
          type: 'copy-anon',
          originalOffset: op.originalOffset,
          length: op.length,
          anonymizedOffset: op.anonymizedOffset,
        })
      }
    }
    const encoded = writeRestoreOpsFrame(filled)
    for (const op of filled) {
      if (op.type === 'literal') wipeBytes(op.bytes)
    }
    if (!encoded.ok) return encoded

    const covering = spans.find(
      (s) => frame.originalStart >= s.start && frame.originalStart < s.end,
    ) ?? { start: frame.originalStart, end: frame.originalEnd }
    rangeDirectory.push({
      spanStart: covering.start,
      spanEnd: covering.end,
      fileOffset: frame.originalStart,
      length: frame.originalEnd - frame.originalStart,
      dataFrameLocalIndex: pieceCount,
      split: frame.split,
    })
    pieceCount += 1
    await input.onFrame({
      plaintext: encoded.value,
      fileOffset: frame.originalStart,
      length: frame.originalEnd - frame.originalStart,
      split: frame.split,
    })
  }

  return recoveryOk({
    originalSha256: hasher.digest(),
    originalByteLength: blobSize,
    pieceCount,
    spans,
    rangeDirectory,
  })
}
