/**
 * Free-text search over the anonymized (transformed) view, returning ranges
 * in original-document coordinates for shared pane highlighting.
 */

import type { PackedMatchIndex } from '../../domain/types.ts'
import { createOffsetMap } from '../../engine/offsetMap.ts'
import { transformSlice, transformWithPlan, type ReplacementPlan } from '../../engine/transform.ts'

export interface AnonSearchMatch {
  readonly from: number
  readonly to: number
}

/** Documents larger than this use line-by-line search instead of a full transform. */
export const LARGE_FULL_TRANSFORM_CHARS = 2_000_000

function findInString(
  haystack: string,
  query: string,
  caseSensitive: boolean,
  maxMatches: number,
): Array<{ from: number; to: number }> {
  if (!query || !haystack) return []
  const hay = caseSensitive ? haystack : haystack.toLowerCase()
  const needle = caseSensitive ? query : query.toLowerCase()
  const results: Array<{ from: number; to: number }> = []
  let pos = 0
  while (results.length < maxMatches) {
    const idx = hay.indexOf(needle, pos)
    if (idx < 0) break
    results.push({ from: idx, to: idx + query.length })
    pos = idx + Math.max(1, needle.length)
  }
  return results
}

/** Map an offset within a transformed line slice back to an absolute original offset. */
function mapAnonOffsetInSlice(
  from: number,
  to: number,
  index: PackedMatchIndex,
  plan: ReplacementPlan,
  anonOffset: number,
): number {
  let origCursor = from
  let anonCursor = 0
  let lo = 0
  let hi = index.starts.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (index.starts[mid]! < from) lo = mid + 1
    else hi = mid
  }
  let i = lo
  while (i > 0 && index.starts[i - 1]! + index.lengths[i - 1]! > from) i--

  for (; i < index.starts.length; i++) {
    const start = index.starts[i]!
    if (start >= to) break
    const end = start + index.lengths[i]!
    const replacement = plan.replacements[i]
    if (replacement == null) continue
    if (start > origCursor) {
      const gap = Math.min(start, to) - origCursor
      if (anonCursor + gap > anonOffset) {
        return origCursor + (anonOffset - anonCursor)
      }
      anonCursor += gap
      origCursor = Math.min(start, to)
    }
    if (start >= from && end <= to) {
      if (anonCursor + replacement.length > anonOffset) {
        // Point into the replaced span → original match start
        return start
      }
      anonCursor += replacement.length
      origCursor = end
    } else {
      const pieceFrom = Math.max(start, from)
      const pieceTo = Math.min(end, to)
      const pieceLen = pieceTo - pieceFrom
      if (anonCursor + pieceLen > anonOffset) {
        return pieceFrom + (anonOffset - anonCursor)
      }
      anonCursor += pieceLen
      origCursor = pieceTo
    }
  }
  if (origCursor < to) {
    const gap = to - origCursor
    if (anonCursor + gap > anonOffset) {
      return origCursor + (anonOffset - anonCursor)
    }
  }
  return Math.min(to, Math.max(from, origCursor))
}

/**
 * Search the anonymized rendering of `original` and return matches as original offsets.
 */
export function findAnonymizedMatches(
  original: string,
  index: PackedMatchIndex,
  plan: ReplacementPlan,
  query: string,
  caseSensitive: boolean,
  maxMatches = 5000,
): AnonSearchMatch[] {
  if (!query) return []

  if (original.length <= LARGE_FULL_TRANSFORM_CHARS) {
    const anon = transformWithPlan(original, index, plan)
    const hits = findInString(anon, query, caseSensitive, maxMatches)
    if (hits.length === 0) return []
    const map = createOffsetMap(index, plan)
    return hits.map((h) => {
      const from = map.outputToOriginal(h.from)
      const to = Math.max(from, map.outputToOriginal(h.to))
      return { from, to }
    })
  }

  // Large logs: search line-by-line without materializing the full transform.
  const results: AnonSearchMatch[] = []
  let lineStart = 0
  while (lineStart <= original.length && results.length < maxMatches) {
    let lineEnd = original.indexOf('\n', lineStart)
    if (lineEnd < 0) lineEnd = original.length
    else lineEnd += 1 // include newline
    const anonLine = transformSlice(original, lineStart, lineEnd, index, plan)
    const hits = findInString(anonLine, query, caseSensitive, maxMatches - results.length)
    for (const h of hits) {
      const from = mapAnonOffsetInSlice(lineStart, lineEnd, index, plan, h.from)
      const to = mapAnonOffsetInSlice(lineStart, lineEnd, index, plan, h.to)
      results.push({ from, to: Math.max(from, to) })
      if (results.length >= maxMatches) return results
    }
    if (lineEnd >= original.length) break
    lineStart = lineEnd
  }
  return results
}
