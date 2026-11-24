import type { LineIndex } from './lineIndex.ts'
import type { PackedMatchIndex } from '../domain/types.ts'
import { firstMatchOnLine, matchesOverlapping } from './packedMatchIndex.ts'

/**
 * Line ↔ match window helpers for viewport / export chunking.
 */
export interface LineMatchWindow {
  line: number
  matchFrom: number
  matchTo: number
  originalFrom: number
  originalTo: number
}

export function lineMatchWindow(
  lineIndex: LineIndex,
  packed: PackedMatchIndex,
  line: number,
): LineMatchWindow {
  const { start, end } = lineIndex.lineContentRange(line)
  // Include terminating newline in originalTo for export windows when needed —
  // content range is enough for decoration replace on the line body.
  const first = firstMatchOnLine(packed, line)
  if (first < 0) {
    return { line, matchFrom: 0, matchTo: 0, originalFrom: start, originalTo: end }
  }
  let to = first
  while (to < packed.lines.length && packed.lines[to] === line) to++
  return {
    line,
    matchFrom: first,
    matchTo: to,
    originalFrom: start,
    originalTo: end,
  }
}

export function matchesForOriginalRange(
  packed: PackedMatchIndex,
  from: number,
  to: number,
): number[] {
  return matchesOverlapping(packed, from, to)
}
