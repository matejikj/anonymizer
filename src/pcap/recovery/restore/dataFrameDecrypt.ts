/**
 * Read selected plaintext DATA frames and assemble original file ranges (step 8).
 * Full-literal v1: one range-directory piece ↔ one DATA frame plaintext.
 *
 * Legacy names `decrypt*` / `Decrypted*` remain for call-site compatibility (T46).
 * They do **not** perform decryption, KDF, or AEAD — recovery v4 stores plaintext frames.
 * Prefer {@link readPlaintextDataFrameAt} / {@link createPlaintextFrameCache} in new code.
 */

import { wipeBytes } from '../../../crypto/wipe'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import { RECOVERY_FRAME_TYPE_DATA } from '../codec/formatConstants'
import { parseFrame } from '../codec/frameCodec'
import { readFullFrameAt } from './recoveryBundleReader'
import type { DataFrameLocation } from './dataFrameDirectory'
import type { PcapRecoveryRestoreEncoding } from '../domain/types'
import { applyRestoreOpsToRange, parseRestoreOpsFrame } from '../codec/literalFrameCodec'

export interface DecryptedFrameCache {
  get(frameIndex: number): Uint8Array | null
  set(frameIndex: number, plaintext: Uint8Array): void
  wipe(): void
}

/** Bounded plaintext DATA cache — wiped on lock. */
export function createPlaintextFrameCache(budgetBytes = 16 * 1024 * 1024): DecryptedFrameCache {
  const map = new Map<number, Uint8Array>()
  let used = 0
  return {
    get(frameIndex) {
      return map.get(frameIndex) ?? null
    },
    set(frameIndex, plaintext) {
      const prev = map.get(frameIndex)
      if (prev) {
        used -= prev.byteLength
        if (prev !== plaintext) wipeBytes(prev)
        map.delete(frameIndex)
      }
      if (plaintext.byteLength > budgetBytes) return
      while (used + plaintext.byteLength > budgetBytes && map.size > 0) {
        const oldest = map.keys().next().value as number
        const v = map.get(oldest)!
        wipeBytes(v)
        used -= v.byteLength
        map.delete(oldest)
      }
      map.set(frameIndex, plaintext)
      used += plaintext.byteLength
    },
    wipe() {
      for (const v of map.values()) wipeBytes(v)
      map.clear()
      used = 0
    },
  }
}

/** @deprecated Legacy name — use {@link createPlaintextFrameCache}. Not cryptographic. */
export function createDecryptedFrameCache(budgetBytes = 16 * 1024 * 1024): DecryptedFrameCache {
  return createPlaintextFrameCache(budgetBytes)
}

/** Preferred name — plaintext frame read (no crypto). */
export async function readPlaintextDataFrameAt(input: {
  recoveryBlob: Blob
  loc: DataFrameLocation
  cache?: DecryptedFrameCache
}): Promise<PcapRecoveryResult<Uint8Array>> {
  const cached = input.cache?.get(input.loc.frameIndex)
  if (cached) return recoveryOk(cached)

  const frame = await readFullFrameAt(input.recoveryBlob, input.loc.fileOffset)
  if (!frame.ok) return frame
  if (frame.value.wireBytes !== input.loc.wireBytes) {
    wipeBytes(frame.value.frameBytes)
    return recoveryFail(PCAP_RECOVERY_ERROR.frameMissing, 'DATA frame length mismatch')
  }

  const parsed = parseFrame(frame.value.frameBytes, 0)
  if (!parsed.ok) {
    wipeBytes(frame.value.frameBytes)
    return parsed
  }
  if (parsed.value.frameType !== RECOVERY_FRAME_TYPE_DATA) {
    wipeBytes(frame.value.frameBytes)
    return recoveryFail(PCAP_RECOVERY_ERROR.frameOrder, 'expected DATA frame')
  }
  if (parsed.value.plaintextLength !== input.loc.plaintextLength) {
    wipeBytes(frame.value.frameBytes)
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'plaintext length mismatch')
  }
  const plaintext = parsed.value.payload.slice()
  wipeBytes(frame.value.frameBytes)

  if (input.cache) {
    input.cache.set(input.loc.frameIndex, plaintext)
  }
  return recoveryOk(plaintext)
}

/** @deprecated Legacy name — use {@link readPlaintextDataFrameAt}. Not cryptographic. */
export async function decryptDataFrameAt(input: {
  recoveryBlob: Blob
  loc: DataFrameLocation
  cache?: DecryptedFrameCache
}): Promise<PcapRecoveryResult<Uint8Array>> {
  return readPlaintextDataFrameAt(input)
}

export interface RangePiece {
  readonly fileOffset: number
  readonly length: number
  readonly dataFrameLocalIndex: number
}

export async function assembleOriginalRange(input: {
  recoveryBlob: Blob
  directory: readonly DataFrameLocation[]
  pieces: readonly RangePiece[]
  rangeStart: number
  rangeEnd: number
  cache?: DecryptedFrameCache
  restoreEncoding?: PcapRecoveryRestoreEncoding
  anonymizedBlob?: Blob | Uint8Array | null
}): Promise<PcapRecoveryResult<Uint8Array>> {
  if (
    input.rangeEnd < input.rangeStart
    || input.rangeEnd - input.rangeStart > PCAP_RECOVERY_LIMITS.maxBundleImportBytes
  ) {
    return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'invalid assemble range')
  }
  const outLen = input.rangeEnd - input.rangeStart
  const out = new Uint8Array(outLen)
  const filled = new Uint8Array(outLen)

  const covering = input.pieces.filter((p) => {
    const pEnd = p.fileOffset + p.length
    return pEnd > input.rangeStart && p.fileOffset < input.rangeEnd
  })
  if (covering.length === 0) {
    return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'no DATA pieces cover range')
  }

  for (const p of covering) {
    const loc = input.directory[p.dataFrameLocalIndex]
    if (!loc) {
      wipeBytes(out)
      return recoveryFail(PCAP_RECOVERY_ERROR.frameMissing, 'DATA frame index out of range')
    }
    const plain = await decryptDataFrameAt({
      recoveryBlob: input.recoveryBlob,
      loc,
      cache: input.cache,
    })
    if (!plain.ok) {
      wipeBytes(out)
      return plain
    }

    if (input.restoreEncoding === 'copy-anonymized-literal-v1') {
      if (!input.anonymizedBlob) {
        if (!input.cache) wipeBytes(plain.value)
        wipeBytes(out)
        return recoveryFail(PCAP_RECOVERY_ERROR.pairMismatch, 'COPY_ANON restore requires anonymized file')
      }
      const parsed = parseRestoreOpsFrame(plain.value)
      if (!parsed.ok) {
        if (!input.cache) wipeBytes(plain.value)
        wipeBytes(out)
        return parsed
      }
      const overlapStart = Math.max(p.fileOffset, input.rangeStart)
      const overlapEnd = Math.min(p.fileOffset + p.length, input.rangeEnd)
      if (overlapEnd > overlapStart) {
        const slice = new Uint8Array(overlapEnd - overlapStart)
        const applied = await applyRestoreOpsToRange({
          ops: parsed.value,
          rangeStart: overlapStart,
          rangeEnd: overlapEnd,
          anonymized: input.anonymizedBlob,
          out: slice,
        })
        if (!applied.ok) {
          if (!input.cache) wipeBytes(plain.value)
          wipeBytes(out)
          return applied
        }
        const dstOff = overlapStart - input.rangeStart
        out.set(slice, dstOff)
        filled.fill(1, dstOff, dstOff + slice.byteLength)
      }
      if (!input.cache) wipeBytes(plain.value)
      continue
    }

    if (plain.value.byteLength !== p.length) {
      if (!input.cache) wipeBytes(plain.value)
      wipeBytes(out)
      return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'piece/plaintext length mismatch')
    }

    const copyStart = Math.max(p.fileOffset, input.rangeStart)
    const copyEnd = Math.min(p.fileOffset + p.length, input.rangeEnd)
    const srcOff = copyStart - p.fileOffset
    const dstOff = copyStart - input.rangeStart
    const n = copyEnd - copyStart
    out.set(plain.value.subarray(srcOff, srcOff + n), dstOff)
    filled.fill(1, dstOff, dstOff + n)
    if (!input.cache) wipeBytes(plain.value)
  }

  for (let i = 0; i < filled.byteLength; i++) {
    if (filled[i] !== 1) {
      wipeBytes(out)
      return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'assemble range has gaps')
    }
  }
  return recoveryOk(out)
}
