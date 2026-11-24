/**
 * Line identity map + per-line column mapping through replacement segments
 * (ARCHITECTURE §4.2 / §4.3).
 */

import type { PackedMatchIndex } from '../domain/types.ts'
import type { ReplacementPlan } from './transform.ts'
import { matchesOverlapping } from './packedMatchIndex.ts'

/** v1: physical line N in original ↔ physical line N in anonymized view. */
export function mapPhysicalLine(line: number): number {
  return line
}

export interface LineColumnMap {
  /** Map column in original line → column in anonymized line (0-based). */
  originalToAnon(originalCol: number): number
  /** Map column in anonymized line → column in original line (0-based). */
  anonToOriginal(anonCol: number): number
  /** Total original line length (excluding newline). */
  originalLength: number
  /** Total anonymized line length (excluding newline). */
  anonLength: number
}

/**
 * Build column mapper for one physical line using active replacements on that line.
 * `lineFrom`/`lineTo` are absolute document offsets of the line content (exclusive of newline).
 */
export function buildLineColumnMap(
  lineFrom: number,
  lineTo: number,
  packed: PackedMatchIndex,
  plan: ReplacementPlan,
): LineColumnMap {
  const ids = matchesOverlapping(packed, lineFrom, lineTo)
  type Seg = { origFrom: number; origTo: number; anonFrom: number; anonTo: number }
  const segs: Seg[] = []
  let anonCursor = 0
  let origCursor = 0
  const lineLen = lineTo - lineFrom

  for (const id of ids) {
    const absStart = packed.starts[id]!
    const absEnd = absStart + packed.lengths[id]!
    const rep = plan.replacements[id]
    if (rep == null) continue
    const localStart = Math.max(0, absStart - lineFrom)
    const localEnd = Math.min(lineLen, absEnd - lineFrom)
    if (localEnd <= localStart) continue

    if (localStart > origCursor) {
      const len = localStart - origCursor
      segs.push({
        origFrom: origCursor,
        origTo: localStart,
        anonFrom: anonCursor,
        anonTo: anonCursor + len,
      })
      anonCursor += len
      origCursor = localStart
    }
    const origLen = localEnd - localStart
    // Full match on this line uses replacement length; clipped edges keep original span length.
    const anonLen =
      absStart >= lineFrom && absEnd <= lineTo ? rep.length : origLen
    segs.push({
      origFrom: localStart,
      origTo: localEnd,
      anonFrom: anonCursor,
      anonTo: anonCursor + anonLen,
    })
    anonCursor += anonLen
    origCursor = localEnd
  }

  if (origCursor < lineLen) {
    const len = lineLen - origCursor
    segs.push({
      origFrom: origCursor,
      origTo: lineLen,
      anonFrom: anonCursor,
      anonTo: anonCursor + len,
    })
    anonCursor += len
  }

  const anonLength = anonCursor

  function originalToAnon(originalCol: number): number {
    const col = clamp(originalCol, 0, lineLen)
    if (col === 0) return 0
    if (col === lineLen) return anonLength
    for (const s of segs) {
      if (col <= s.origFrom) return s.anonFrom
      if (col < s.origTo) {
        const origSpan = s.origTo - s.origFrom
        const anonSpan = s.anonTo - s.anonFrom
        if (origSpan === anonSpan) return s.anonFrom + (col - s.origFrom)
        // Inside a replacement span → map to start of replacement (§4.3)
        return s.anonFrom
      }
      // col === s.origTo → continue; next segment starts here
    }
    return anonLength
  }

  function anonToOriginal(anonCol: number): number {
    const col = clamp(anonCol, 0, anonLength)
    if (col === 0) return 0
    if (col === anonLength) return lineLen
    for (const s of segs) {
      if (col <= s.anonFrom) return s.origFrom
      if (col < s.anonTo) {
        const origSpan = s.origTo - s.origFrom
        const anonSpan = s.anonTo - s.anonFrom
        if (origSpan === anonSpan) return s.origFrom + (col - s.anonFrom)
        // Inside replacement → map to start of original span (§4.3)
        return s.origFrom
      }
    }
    return lineLen
  }

  return { originalToAnon, anonToOriginal, originalLength: lineLen, anonLength }
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n))
}
