/**
 * DATA plaintext codec for copy-anonymized-literal-v1.
 *
 * Each DATA frame is independently parseable:
 *   magic "RCOPS001" (8)
 *   opCount u32
 *   ops:
 *     LITERAL    u8=1  originalOffset u32  length u32  bytes[length]
 *     COPY_ANON  u8=2  originalOffset u32  length u32  anonymizedOffset u32
 *
 * Ops cover original file offsets in strictly increasing, non-overlapping order.
 * COPY_ANON anonymized offsets are also strictly increasing and non-overlapping.
 */

import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import { RecoveryReader, RecoveryWriter } from './binaryIO'
import {
  RECOVERY_OP_COPY_ANON,
  RECOVERY_OP_COPY_ANON_BYTES,
  RECOVERY_OP_LITERAL,
  RECOVERY_OP_LITERAL_HEADER_BYTES,
  RECOVERY_RESTORE_OPS_FRAME_HEADER_BYTES,
  RECOVERY_RESTORE_OPS_MAGIC,
  RECOVERY_RESTORE_OPS_MAGIC_ASCII,
} from './formatConstants'

export type RestoreOpLiteral = {
  readonly type: 'literal'
  readonly originalOffset: number
  readonly length: number
  readonly bytes: Uint8Array
}

export type RestoreOpCopyAnon = {
  readonly type: 'copy-anon'
  readonly originalOffset: number
  readonly length: number
  readonly anonymizedOffset: number
}

export type RestoreOp = RestoreOpLiteral | RestoreOpCopyAnon

export type RestoreOpPlan =
  | { readonly type: 'literal'; readonly originalOffset: number; readonly length: number }
  | {
      readonly type: 'copy-anon'
      readonly originalOffset: number
      readonly length: number
      readonly anonymizedOffset: number
    }

export function encodedRestoreOpSize(op: RestoreOpPlan | RestoreOp): number {
  return op.type === 'literal'
    ? RECOVERY_OP_LITERAL_HEADER_BYTES + op.length
    : RECOVERY_OP_COPY_ANON_BYTES
}

export function encodedRestoreFrameSize(ops: readonly (RestoreOpPlan | RestoreOp)[]): number {
  let n = RECOVERY_RESTORE_OPS_FRAME_HEADER_BYTES
  for (const op of ops) n += encodedRestoreOpSize(op)
  return n
}

export function writeRestoreOpsFrame(ops: readonly RestoreOp[]): PcapRecoveryResult<Uint8Array> {
  if (ops.length > 0xffff_ffff) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many restore ops in frame')
  }
  const size = encodedRestoreFrameSize(ops)
  if (size > PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'restore-op frame exceeds plaintext limit')
  }
  const w = new RecoveryWriter()
  w.writeBytes(RECOVERY_RESTORE_OPS_MAGIC)
  w.writeU32(ops.length)
  for (const op of ops) {
    if (op.type === 'literal') {
      if (op.bytes.byteLength !== op.length) {
        return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'literal length mismatch')
      }
      w.writeU8(RECOVERY_OP_LITERAL)
      w.writeU32(op.originalOffset)
      w.writeU32(op.length)
      w.writeBytes(op.bytes)
    } else {
      w.writeU8(RECOVERY_OP_COPY_ANON)
      w.writeU32(op.originalOffset)
      w.writeU32(op.length)
      w.writeU32(op.anonymizedOffset)
    }
  }
  if (w.byteLength !== size) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'restore-op frame size mismatch')
  }
  return recoveryOk(w.toUint8Array())
}

export function parseRestoreOpsFrame(bytes: Uint8Array): PcapRecoveryResult<RestoreOp[]> {
  if (bytes.byteLength > PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'restore-op frame exceeds plaintext limit')
  }
  if (bytes.byteLength < RECOVERY_RESTORE_OPS_FRAME_HEADER_BYTES) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'truncated restore-op frame')
  }
  const r = new RecoveryReader(bytes)
  const magic = r.readBytes(8, 8)
  if (!magic.ok) return magic
  if (new TextDecoder().decode(magic.value) !== RECOVERY_RESTORE_OPS_MAGIC_ASCII) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'invalid restore-op magic')
  }
  const opCount = r.readU32()
  if (!opCount.ok) return opCount
  if (opCount.value > PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many restore ops')
  }

  const ops: RestoreOp[] = []
  let prevOrigEnd = -1
  let prevAnonEnd = -1
  for (let i = 0; i < opCount.value; i++) {
    const type = r.readU8()
    if (!type.ok) return type
    const originalOffset = r.readU32()
    if (!originalOffset.ok) return originalOffset
    const length = r.readU32()
    if (!length.ok) return length
    if (length.value <= 0) {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'empty restore op')
    }
    if (length.value > PCAP_RECOVERY_LIMITS.maxBundleImportBytes) {
      return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'restore op exceeds limit')
    }
    if (prevOrigEnd >= 0 && originalOffset.value < prevOrigEnd) {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'restore ops overlap or go backwards')
    }
    prevOrigEnd = originalOffset.value + length.value

    if (type.value === RECOVERY_OP_LITERAL) {
      const payload = r.readBytes(length.value, PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes)
      if (!payload.ok) return payload
      ops.push({
        type: 'literal',
        originalOffset: originalOffset.value,
        length: length.value,
        bytes: payload.value,
      })
    } else if (type.value === RECOVERY_OP_COPY_ANON) {
      const anonymizedOffset = r.readU32()
      if (!anonymizedOffset.ok) return anonymizedOffset
      if (prevAnonEnd >= 0 && anonymizedOffset.value < prevAnonEnd) {
        return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'COPY_ANON offsets overlap or go backwards')
      }
      prevAnonEnd = anonymizedOffset.value + length.value
      ops.push({
        type: 'copy-anon',
        originalOffset: originalOffset.value,
        length: length.value,
        anonymizedOffset: anonymizedOffset.value,
      })
    } else {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'unknown restore op')
    }
  }
  const trailing = r.expectConsumed()
  if (!trailing.ok) return trailing
  return recoveryOk(ops)
}

export async function readAnonymizedSlice(
  source: Blob | Uint8Array,
  offset: number,
  length: number,
): Promise<PcapRecoveryResult<Uint8Array>> {
  if (!Number.isInteger(offset) || !Number.isInteger(length) || offset < 0 || length < 0) {
    return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'invalid COPY_ANON range')
  }
  if (length > PCAP_RECOVERY_LIMITS.maxBundleImportBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'COPY_ANON range exceeds limit')
  }
  const size = source instanceof Uint8Array ? source.byteLength : source.size
  if (offset + length > size) {
    return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'COPY_ANON range past anonymized end')
  }
  if (source instanceof Uint8Array) {
    return recoveryOk(source.subarray(offset, offset + length).slice())
  }
  const ab = await source.slice(offset, offset + length).arrayBuffer()
  return recoveryOk(new Uint8Array(ab))
}

/**
 * Materialize original bytes for [rangeStart, rangeEnd) from decoded ops.
 */
export async function applyRestoreOpsToRange(input: {
  ops: readonly RestoreOp[]
  rangeStart: number
  rangeEnd: number
  anonymized: Blob | Uint8Array
  out: Uint8Array
}): Promise<PcapRecoveryResult<void>> {
  const { rangeStart, rangeEnd, out } = input
  if (out.byteLength !== rangeEnd - rangeStart) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'restore output length mismatch')
  }
  const filled = new Uint8Array(out.byteLength)
  for (const op of input.ops) {
    const opEnd = op.originalOffset + op.length
    if (opEnd <= rangeStart || op.originalOffset >= rangeEnd) continue
    const copyStart = Math.max(op.originalOffset, rangeStart)
    const copyEnd = Math.min(opEnd, rangeEnd)
    const n = copyEnd - copyStart
    const srcOff = copyStart - op.originalOffset
    const dstOff = copyStart - rangeStart
    if (op.type === 'literal') {
      if (srcOff + n > op.bytes.byteLength) {
        return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'literal payload truncated')
      }
      out.set(op.bytes.subarray(srcOff, srcOff + n), dstOff)
      filled.fill(1, dstOff, dstOff + n)
    } else {
      const slice = await readAnonymizedSlice(
        input.anonymized,
        op.anonymizedOffset + srcOff,
        n,
      )
      if (!slice.ok) return slice
      out.set(slice.value, dstOff)
      filled.fill(1, dstOff, dstOff + n)
    }
  }
  for (let i = 0; i < filled.byteLength; i++) {
    if (filled[i] !== 1) {
      return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'restore range has gaps')
    }
  }
  return recoveryOk(undefined)
}
