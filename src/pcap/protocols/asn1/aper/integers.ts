/**
 * T56 — APER constrained integers / enumerations (aligned variant, X.691 §11.5.7 / §13.2.6).
 */

import { BitCursor, type BitSpan } from './bitCursor.ts'
import { constrainedBitWidth } from './lengthDeterminant.ts'

export interface IntDecode {
  readonly value: number
  readonly span: BitSpan
}

export type ConstrainedWholeCase =
  | 'empty'
  | 'bit-field'
  | 'one-octet'
  | 'two-octet'
  | 'indefinite'

/** ALIGNED variant case split per X.691 §11.5.7. */
export function constrainedWholeNumberCase(range: number): ConstrainedWholeCase {
  if (range <= 1) return 'empty'
  if (range <= 255) return 'bit-field'
  if (range === 256) return 'one-octet'
  if (range <= 65536) return 'two-octet'
  return 'indefinite'
}

/** Minimum octets for a non-negative-binary-integer (§11.3.6). */
export function minOctetsNonNegativeBinary(n: number): number {
  if (n <= 0) return 1
  let bits = 0
  let v = n
  while (v > 0) {
    bits++
    v = Math.floor(v / 2)
  }
  return Math.max(1, Math.ceil(bits / 8))
}

/**
 * Octets required to hold every offset in a constrained range (§13.2.6 length-determinant ub).
 */
export function octetsToHoldIntegerRange(range: number): number {
  if (range <= 1) return 0
  return minOctetsNonNegativeBinary(range - 1)
}

/** @deprecated Use {@link octetsToHoldIntegerRange}; kept for registry exports. */
export function constrainedIntegerOctets(range: number): number {
  return octetsToHoldIntegerRange(range)
}

function readFixedOctets(cur: BitCursor, octets: number): number | null {
  let value = 0
  for (let i = 0; i < octets; i++) {
    const b = cur.readBits(8)
    if (b === null) return null
    value = value * 256 + b
  }
  return value
}

function writeFixedOctets(cur: BitCursor, octets: number, value: number): boolean {
  for (let i = octets - 1; i >= 0; i--) {
    const divisor = 256 ** i
    const byte = Math.floor(value / divisor) % 256
    if (!cur.writeBits(8, byte)) return false
  }
  return true
}

/**
 * Constrained whole number in [lower, upper] inclusive (§11.5.7 ALIGNED only).
 * Does not apply §13.2.6 integer length prefix for the indefinite case.
 */
export function readConstrainedWholeNumber(
  cur: BitCursor,
  lower: number,
  upper: number,
): IntDecode | null {
  if (upper < lower) return null
  const range = upper - lower + 1
  const start = cur.absoluteBitOffset
  const kind = constrainedWholeNumberCase(range)

  if (kind === 'empty') {
    return { value: lower, span: { bitOffset: start, bitLength: 0 } }
  }

  if (kind === 'bit-field') {
    const bits = constrainedBitWidth(range)
    const offset = cur.readBits(bits)
    if (offset === null) return null
    if (offset >= range) return null
    return {
      value: lower + offset,
      span: { bitOffset: start, bitLength: cur.absoluteBitOffset - start },
    }
  }

  if (!cur.align()) return null

  if (kind === 'one-octet') {
    const offset = readFixedOctets(cur, 1)
    if (offset === null || offset >= range) return null
    return {
      value: lower + offset,
      span: { bitOffset: start, bitLength: cur.absoluteBitOffset - start },
    }
  }

  if (kind === 'two-octet') {
    const offset = readFixedOctets(cur, 2)
    if (offset === null || offset >= range) return null
    return {
      value: lower + offset,
      span: { bitOffset: start, bitLength: cur.absoluteBitOffset - start },
    }
  }

  // §11.5.7.4 value body without §13.2.6 length — use readConstrainedInteger for INTEGER types.
  return null
}

export function writeConstrainedWholeNumber(
  cur: BitCursor,
  lower: number,
  upper: number,
  value: number,
): boolean {
  if (value < lower || value > upper) return false
  const range = upper - lower + 1
  const offset = value - lower
  const kind = constrainedWholeNumberCase(range)

  if (kind === 'empty') return true

  if (kind === 'bit-field') {
    const bits = constrainedBitWidth(range)
    return cur.writeBits(bits, offset)
  }

  if (!cur.align()) return false

  if (kind === 'one-octet') {
    return writeFixedOctets(cur, 1, offset)
  }

  if (kind === 'two-octet') {
    return writeFixedOctets(cur, 2, offset)
  }

  return false
}

/**
 * INTEGER type field encoding (§13.2.2 + §13.2.6 when range > 64K).
 */
export function readConstrainedInteger(
  cur: BitCursor,
  lower: number,
  upper: number,
): IntDecode | null {
  if (upper < lower) return null
  const range = upper - lower + 1
  const start = cur.absoluteBitOffset

  if (constrainedWholeNumberCase(range) !== 'indefinite') {
    return readConstrainedWholeNumber(cur, lower, upper)
  }

  const lenUb = octetsToHoldIntegerRange(range)
  const lenDec = readConstrainedWholeNumber(cur, 1, lenUb)
  if (!lenDec) return null
  const len = lenDec.value
  if (len < 1 || len > lenUb) return null
  if (!cur.align()) return null
  const offset = readFixedOctets(cur, len)
  if (offset === null || offset >= range) return null
  return {
    value: lower + offset,
    span: { bitOffset: start, bitLength: cur.absoluteBitOffset - start },
  }
}

export function writeConstrainedInteger(
  cur: BitCursor,
  lower: number,
  upper: number,
  value: number,
): boolean {
  if (value < lower || value > upper) return false
  const range = upper - lower + 1
  const offset = value - lower

  if (constrainedWholeNumberCase(range) !== 'indefinite') {
    return writeConstrainedWholeNumber(cur, lower, upper, value)
  }

  const len = minOctetsNonNegativeBinary(offset)
  const lenUb = octetsToHoldIntegerRange(range)
  if (len > lenUb) return false
  if (!writeConstrainedWholeNumber(cur, 1, lenUb, len)) return false
  if (!cur.align()) return false
  return writeFixedOctets(cur, len, offset)
}

/** Bit length of an INTEGER field encoding for a concrete value. */
export function constrainedIntegerFieldBitLength(
  lower: number,
  upper: number,
  value: number,
): number | null {
  const buf = new Uint8Array(32)
  const cur = new BitCursor(buf)
  if (!writeConstrainedInteger(cur, lower, upper, value)) return null
  // BitCursor constructed at byte 0 — absolute offset is the field width.
  return cur.absoluteBitOffset
}

export function readEnumerated(
  cur: BitCursor,
  count: number,
  extensible: boolean,
): IntDecode | null {
  if (count <= 0) return null
  if (extensible) {
    const start = cur.absoluteBitOffset
    const ext = cur.readBits(1)
    if (ext === null) return null
    if (ext === 1) {
      return null
    }
    const inner = readConstrainedWholeNumber(cur, 0, count - 1)
    if (!inner) return null
    return {
      value: inner.value,
      span: { bitOffset: start, bitLength: cur.absoluteBitOffset - start },
    }
  }
  return readConstrainedWholeNumber(cur, 0, count - 1)
}

export function writeEnumerated(
  cur: BitCursor,
  count: number,
  extensible: boolean,
  index: number,
): boolean {
  if (index < 0 || index >= count) return false
  if (extensible) {
    if (!cur.writeBits(1, 0)) return false
  }
  return writeConstrainedWholeNumber(cur, 0, count - 1, index)
}

export function readBoolean(cur: BitCursor): { value: boolean; span: BitSpan } | null {
  const start = cur.absoluteBitOffset
  const b = cur.readBits(1)
  if (b === null) return null
  return { value: b === 1, span: { bitOffset: start, bitLength: 1 } }
}

export function writeBoolean(cur: BitCursor, value: boolean): boolean {
  return cur.writeBits(1, value ? 1 : 0)
}

/** Encode constrained integer into a fresh scratch; returns used byte length. */
export function encodeConstrainedIntegerBytes(
  lower: number,
  upper: number,
  value: number,
  maxBytes = 16,
): Uint8Array | null {
  const buf = new Uint8Array(maxBytes)
  const cur = new BitCursor(buf)
  if (!writeConstrainedInteger(cur, lower, upper, value)) return null
  if (!cur.align()) return null
  const bytes = (cur.bitOffset + 7) >> 3
  return buf.subarray(0, bytes)
}
