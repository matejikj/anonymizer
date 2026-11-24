/**
 * Unsigned LEB128 / delta helpers for compact occurrence lists.
 */

import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'

export function writeVarintU32(value: number, out: number[]): void {
  let v = value >>> 0
  while (v >= 0x80) {
    out.push((v & 0x7f) | 0x80)
    v >>>= 7
  }
  out.push(v)
}

export function readVarintU32(
  bytes: Uint8Array,
  offset: number,
): PcapRecoveryResult<{ value: number; next: number }> {
  let result = 0
  let shift = 0
  let pos = offset
  while (pos < bytes.byteLength) {
    const b = bytes[pos]!
    pos += 1
    result |= (b & 0x7f) << shift
    if ((b & 0x80) === 0) {
      return recoveryOk({ value: result >>> 0, next: pos })
    }
    shift += 7
    if (shift > 35) {
      return recoveryFail(PCAP_RECOVERY_ERROR.indexInvalid, 'varint overflow')
    }
  }
  return recoveryFail(PCAP_RECOVERY_ERROR.indexInvalid, 'truncated varint')
}

/** Encode strictly increasing u32 sequence as first absolute + deltas. */
export function encodeDeltaVarints(sorted: readonly number[]): Uint8Array {
  const tmp: number[] = []
  let prev = 0
  for (let i = 0; i < sorted.length; i++) {
    const v = sorted[i]! >>> 0
    const delta = i === 0 ? v : v - prev
    writeVarintU32(delta, tmp)
    prev = v
  }
  return Uint8Array.from(tmp)
}

export function decodeDeltaVarints(
  bytes: Uint8Array,
  expectedCount: number,
): PcapRecoveryResult<Uint32Array> {
  const out = new Uint32Array(expectedCount)
  let offset = 0
  let prev = 0
  for (let i = 0; i < expectedCount; i++) {
    const step = readVarintU32(bytes, offset)
    if (!step.ok) return step
    const v = i === 0 ? step.value.value : prev + step.value.value
    out[i] = v >>> 0
    prev = v
    offset = step.value.next
  }
  if (offset !== bytes.byteLength) {
    return recoveryFail(PCAP_RECOVERY_ERROR.indexInvalid, 'trailing varint bytes')
  }
  return recoveryOk(out)
}
