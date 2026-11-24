import type { Entity, PackedMatchIndex, ResolvedMatch } from '../domain/types.ts'

export const FLAG_ENABLED = 1

export interface PackedMatchBuffers {
  starts: ArrayBuffer
  lengths: ArrayBuffer
  lines: ArrayBuffer
  entityIndexes: ArrayBuffer
  flags: ArrayBuffer
  count: number
}

export function packResolvedMatches(
  matches: ResolvedMatch[],
  entityIndexByKey: Map<string, number>,
  entityEnabled: (key: string) => boolean = () => true,
): PackedMatchIndex {
  const n = matches.length
  const starts = new Uint32Array(n)
  const lengths = new Uint32Array(n)
  const lines = new Uint32Array(n)
  const entityIndexes = new Uint32Array(n)
  const flags = new Uint16Array(n)
  for (let i = 0; i < n; i++) {
    const m = matches[i]!
    starts[i] = m.start
    lengths[i] = m.end - m.start
    lines[i] = m.line
    entityIndexes[i] = entityIndexByKey.get(m.entityKey) ?? 0
    flags[i] = entityEnabled(m.entityKey) ? FLAG_ENABLED : 0
  }
  return { starts, lengths, lines, entityIndexes, flags }
}

export function entityKeyToIndex(entities: Entity[]): Map<string, number> {
  const map = new Map<string, number>()
  for (let i = 0; i < entities.length; i++) {
    map.set(entities[i]!.key, i)
  }
  return map
}

export function toTransferableBuffers(index: PackedMatchIndex): {
  buffers: PackedMatchBuffers
  transfer: ArrayBuffer[]
} {
  const buffers: PackedMatchBuffers = {
    starts: index.starts.buffer as ArrayBuffer,
    lengths: index.lengths.buffer as ArrayBuffer,
    lines: index.lines.buffer as ArrayBuffer,
    entityIndexes: index.entityIndexes.buffer as ArrayBuffer,
    flags: index.flags.buffer as ArrayBuffer,
    count: index.starts.length,
  }
  return {
    buffers,
    transfer: [
      buffers.starts,
      buffers.lengths,
      buffers.lines,
      buffers.entityIndexes,
      buffers.flags,
    ],
  }
}

export function fromTransferableBuffers(buffers: PackedMatchBuffers): PackedMatchIndex {
  return {
    starts: new Uint32Array(buffers.starts),
    lengths: new Uint32Array(buffers.lengths),
    lines: new Uint32Array(buffers.lines),
    entityIndexes: new Uint32Array(buffers.entityIndexes),
    flags: new Uint16Array(buffers.flags),
  }
}

/** Binary search first match with start >= from. */
export function lowerBoundStart(index: PackedMatchIndex, from: number): number {
  let lo = 0
  let hi = index.starts.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (index.starts[mid]! < from) lo = mid + 1
    else hi = mid
  }
  return lo
}

/** Matches overlapping [from, to). */
export function matchesOverlapping(
  index: PackedMatchIndex,
  from: number,
  to: number,
): number[] {
  const out: number[] = []
  let i = lowerBoundStart(index, from)
  while (i > 0 && index.starts[i - 1]! + index.lengths[i - 1]! > from) i--
  for (; i < index.starts.length; i++) {
    const start = index.starts[i]!
    if (start >= to) break
    const end = start + index.lengths[i]!
    if (end > from) out.push(i)
  }
  return out
}

/** First match index on a given 1-based line (or -1). */
export function firstMatchOnLine(index: PackedMatchIndex, line: number): number {
  let lo = 0
  let hi = index.lines.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (index.lines[mid]! < line) lo = mid + 1
    else hi = mid
  }
  if (lo < index.lines.length && index.lines[lo] === line) return lo
  return -1
}
