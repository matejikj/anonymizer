/**
 * T56 — APER length determinants (X.691 §11): normally-small / constrained / fragmented.
 * Fragmented form (>16K) supported for decode bounds only; encode baseline uses ≤16K.
 */

import type { BitCursor } from './bitCursor.ts'

export interface LengthRead {
  readonly length: number
  readonly spanBitOffset: number
  readonly spanBitLength: number
}

/**
 * Normally small length (0..63 in 1+6 bits, else unconstrained with length determinant).
 * Used for normally-small non-negative whole numbers and some length forms.
 */
export function readNormallySmallLength(cur: BitCursor): LengthRead | null {
  const start = cur.absoluteBitOffset
  const flag = cur.readBits(1)
  if (flag === null) return null
  if (flag === 0) {
    const v = cur.readBits(6)
    if (v === null) return null
    return {
      length: v,
      spanBitOffset: start,
      spanBitLength: cur.absoluteBitOffset - start,
    }
  }
  // else: unconstrained length determinant (aligned)
  if (!cur.align()) return null
  return readUnconstrainedLength(cur, start)
}

/**
 * Constrained whole number range size → bit width for non-negative offset into range.
 * X.691: bits = ceil(log2(range)) when range >= 2; 0 bits when range == 1.
 */
export function constrainedBitWidth(range: number): number {
  if (range <= 1) return 0
  // Do not use >>> — it truncates to 32-bit and under-counts AMF 40-bit ranges.
  let bits = 0
  let r = range - 1
  while (r > 0) {
    bits++
    r = Math.floor(r / 2)
  }
  return bits
}

/** Unconstrained length determinant after octet alignment (single/fragmented). */
export function readUnconstrainedLength(cur: BitCursor, startBit?: number): LengthRead | null {
  const start = startBit ?? cur.absoluteBitOffset
  if (!cur.align()) return null
  const b0 = cur.readBits(8)
  if (b0 === null) return null
  if (b0 < 128) {
    return {
      length: b0,
      spanBitOffset: start,
      spanBitLength: cur.absoluteBitOffset - start,
    }
  }
  if (b0 === 0x80 + 1) {
    // indefinite / reserved — reject for PCAP safety
    cur.clearIssue()
    return null
  }
  if ((b0 & 0xc0) === 0x80) {
    // short form 1–2 byte length (128..16K-1): lower 6 bits = count of following octets? 
    // X.691: if bit 8=1 and bit 7=0, bits 6-1 give number of octets for length (1 or 2 typically)
    const n = b0 & 0x3f
    if (n === 0 || n > 2) return null
    let len = 0
    for (let i = 0; i < n; i++) {
      const b = cur.readBits(8)
      if (b === null) return null
      len = (len << 8) | b
    }
    return {
      length: len,
      spanBitOffset: start,
      spanBitLength: cur.absoluteBitOffset - start,
    }
  }
  // Fragmented: 11xxxxxx where lower 6 bits are multiplier of 16K (1..4)
  if ((b0 & 0xc0) === 0xc0) {
    const m = b0 & 0x3f
    if (m < 1 || m > 4) return null
    const fragment = m * 16384
    return {
      length: fragment,
      spanBitOffset: start,
      spanBitLength: cur.absoluteBitOffset - start,
    }
  }
  return null
}

export function writeUnconstrainedLength(cur: BitCursor, length: number): boolean {
  if (length < 0 || length >= 16384) return false
  if (!cur.align()) return false
  if (length < 128) return cur.writeBits(8, length)
  // two-octet length: 0x82 | hi | lo
  if (!cur.writeBits(8, 0x82)) return false
  if (!cur.writeBits(8, (length >>> 8) & 0xff)) return false
  return cur.writeBits(8, length & 0xff)
}

export function writeNormallySmallLength(cur: BitCursor, length: number): boolean {
  if (length < 0) return false
  if (length < 64) {
    if (!cur.writeBits(1, 0)) return false
    return cur.writeBits(6, length)
  }
  if (!cur.writeBits(1, 1)) return false
  return writeUnconstrainedLength(cur, length)
}
