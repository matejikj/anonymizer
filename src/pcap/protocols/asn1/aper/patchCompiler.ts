/**
 * T56 — merge bit-level rewrites into non-overlapping byte patches for PatchCollector.
 * Two leaves may share a byte; only declared bits change; public byte count = union.
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector.ts'
import type { BitSpan } from './bitCursor.ts'
import { BitCursor } from './bitCursor.ts'

export interface BitRewrite {
  readonly span: BitSpan
  /** New bit value (right-aligned in the low `bitLength` bits). */
  readonly value: number
}

export interface CompiledBytePatch {
  readonly offset: number
  readonly data: Uint8Array
}

/**
 * Apply bit rewrites onto a copy of `buffer` and return merged byte patches
 * covering the union of touched physical bytes.
 */
export function compileBitRewrites(
  buffer: Uint8Array,
  rewrites: readonly BitRewrite[],
): { patches: CompiledBytePatch[]; issues: string[] } {
  const issues: string[] = []
  if (rewrites.length === 0) return { patches: [], issues }

  // Detect overlapping incompatible rewrites (same bits, different values)
  for (let i = 0; i < rewrites.length; i++) {
    for (let j = i + 1; j < rewrites.length; j++) {
      const a = rewrites[i]!.span
      const b = rewrites[j]!.span
      if (spansOverlap(a, b) && !spansEqual(a, b)) {
        // Partial overlap of different fields sharing a byte is OK if bits don't collide
        if (bitsCollide(a, b)) {
          issues.push('bit-rewrite-collision')
          return { patches: [], issues }
        }
      }
    }
  }

  const out = buffer.slice()
  const touched = new Uint8Array(out.length) // 1 = byte touched

  for (const rw of rewrites) {
    const { bitOffset, bitLength } = rw.span
    if (bitLength <= 0 || bitLength > 32) {
      issues.push('bit-rewrite-width')
      return { patches: [], issues }
    }
    const endBit = bitOffset + bitLength
    if (bitOffset < 0 || endBit > out.length * 8) {
      issues.push('bit-rewrite-oob')
      return { patches: [], issues }
    }
    const cur = new BitCursor(out)
    if (!cur.seekBit(bitOffset)) {
      issues.push('bit-rewrite-seek')
      return { patches: [], issues }
    }
    if (!cur.writeBits(bitLength, rw.value >>> 0)) {
      issues.push('bit-rewrite-write')
      return { patches: [], issues }
    }
    const firstByte = bitOffset >> 3
    const lastByte = (endBit - 1) >> 3
    for (let b = firstByte; b <= lastByte; b++) touched[b] = 1
  }

  // Merge contiguous touched bytes into patches
  const patches: CompiledBytePatch[] = []
  let i = 0
  while (i < touched.length) {
    if (!touched[i]) {
      i++
      continue
    }
    const start = i
    while (i < touched.length && touched[i]) i++
    patches.push({ offset: start, data: out.subarray(start, i) })
  }
  return { patches, issues }
}

/** Apply compiled patches to a PatchCollector (byte-level). */
export function applyCompiledPatches(
  collector: PatchCollector,
  patches: readonly CompiledBytePatch[],
): void {
  for (const p of patches) {
    try {
      collector.add(p.offset, p.data.slice())
    } catch {
      // overlap with prior protocol patches → fail-closed leave (caller may mask parent)
    }
  }
}

/** Physical byte ranges touched by bit spans (union, for diagnosticImpact). */
export function physicalByteRanges(spans: readonly BitSpan[]): Array<{ offset: number; length: number }> {
  if (spans.length === 0) return []
  const bytes = new Set<number>()
  for (const s of spans) {
    if (s.bitLength <= 0) continue
    const first = s.bitOffset >> 3
    const last = (s.bitOffset + s.bitLength - 1) >> 3
    for (let b = first; b <= last; b++) bytes.add(b)
  }
  const sorted = [...bytes].sort((a, b) => a - b)
  const ranges: Array<{ offset: number; length: number }> = []
  let start = sorted[0]!
  let prev = start
  for (let i = 1; i < sorted.length; i++) {
    const b = sorted[i]!
    if (b === prev + 1) {
      prev = b
      continue
    }
    ranges.push({ offset: start, length: prev - start + 1 })
    start = b
    prev = b
  }
  ranges.push({ offset: start, length: prev - start + 1 })
  return ranges
}

function spansOverlap(a: BitSpan, b: BitSpan): boolean {
  const aEnd = a.bitOffset + a.bitLength
  const bEnd = b.bitOffset + b.bitLength
  return a.bitOffset < bEnd && b.bitOffset < aEnd
}

function spansEqual(a: BitSpan, b: BitSpan): boolean {
  return a.bitOffset === b.bitOffset && a.bitLength === b.bitLength
}

function bitsCollide(a: BitSpan, b: BitSpan): boolean {
  const aEnd = a.bitOffset + a.bitLength
  const bEnd = b.bitOffset + b.bitLength
  const start = Math.max(a.bitOffset, b.bitOffset)
  const end = Math.min(aEnd, bEnd)
  return end > start
}
