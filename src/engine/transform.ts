import type { Entity, PackedMatchIndex, ResolvedMatch, TransformSegment } from '../domain/types.ts'
import {
  assertResolvedNonOverlapping,
  assertSameLineCount,
  assertNoNewline,
} from '../domain/invariants.ts'
import { FLAG_ENABLED } from './packedMatchIndex.ts'
import { fenwickBuild } from './fenwick.ts'
import { createOffsetMap } from './offsetMap.ts'
import type { OffsetMap } from '../domain/types.ts'

export interface ReplacementPlan {
  /** Parallel to PackedMatchIndex rows: replacement string when enabled, else null. */
  replacements: Array<string | null>
  /** length(replacement) - length(original) per match; 0 if disabled. */
  lengthDeltas: Int32Array
  fenwick: Int32Array
}

export function buildReplacementPlan(
  index: PackedMatchIndex,
  entities: Entity[],
): ReplacementPlan {
  const n = index.starts.length
  const replacements: Array<string | null> = new Array(n)
  const lengthDeltas = new Int32Array(n)
  for (let i = 0; i < n; i++) {
    const enabled = (index.flags[i]! & FLAG_ENABLED) !== 0
    const entity = entities[index.entityIndexes[i]!]
    if (!enabled || !entity) {
      replacements[i] = null
      lengthDeltas[i] = 0
      continue
    }
    assertNoNewline(entity.replacement, 'replacement')
    replacements[i] = entity.replacement
    lengthDeltas[i] = entity.replacement.length - index.lengths[i]!
  }
  return {
    replacements,
    lengthDeltas,
    fenwick: fenwickBuild(lengthDeltas),
  }
}

/**
 * Reference full-document transform (ARCHITECTURE §2 / §7.5).
 * Builds output from original + resolved matches; never chained replace().
 */
export function transform(
  original: string,
  matches: ResolvedMatch[],
  entitiesByKey: Map<string, Entity>,
): string {
  assertResolvedNonOverlapping(matches)
  if (matches.length === 0) return original

  const parts: string[] = []
  let cursor = 0
  for (const m of matches) {
    const entity = entitiesByKey.get(m.entityKey)
    if (!entity || !entity.enabled) continue
    assertNoNewline(entity.replacement, 'replacement')
    if (m.start > cursor) parts.push(original.slice(cursor, m.start))
    parts.push(entity.replacement)
    cursor = m.end
  }
  if (cursor < original.length) parts.push(original.slice(cursor))
  const out = parts.join('')
  assertSameLineCount(original, out)
  return out
}

/** Transform using packed index + plan (must equal reference transform). */
export function transformWithPlan(
  original: string,
  index: PackedMatchIndex,
  plan: ReplacementPlan,
): string {
  return transformSlice(original, 0, original.length, index, plan)
}

export function transformSlice(
  original: string,
  from: number,
  to: number,
  index: PackedMatchIndex,
  plan: ReplacementPlan,
): string {
  const parts: string[] = []
  let cursor = from
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
    if (start > cursor) parts.push(original.slice(cursor, Math.min(start, to)))
    if (start >= from && end <= to) {
      parts.push(replacement)
    } else {
      parts.push(original.slice(Math.max(start, from), Math.min(end, to)))
    }
    cursor = Math.max(cursor, end)
  }
  if (cursor < to) parts.push(original.slice(cursor, to))
  return parts.join('')
}

export function buildTransformSegments(
  matches: ResolvedMatch[],
  entitiesByKey: Map<string, Entity>,
): TransformSegment[] {
  const segments: TransformSegment[] = []
  let outputCursor = 0
  let originalCursor = 0
  for (const m of matches) {
    const entity = entitiesByKey.get(m.entityKey)
    if (!entity || !entity.enabled) continue
    if (m.start > originalCursor) {
      const len = m.start - originalCursor
      segments.push({
        originalFrom: originalCursor,
        originalTo: m.start,
        outputFrom: outputCursor,
        outputTo: outputCursor + len,
        line: m.line,
      })
      outputCursor += len
    }
    const rep = entity.replacement
    segments.push({
      originalFrom: m.start,
      originalTo: m.end,
      outputFrom: outputCursor,
      outputTo: outputCursor + rep.length,
      line: m.line,
      entityKey: m.entityKey,
    })
    outputCursor += rep.length
    originalCursor = m.end
  }
  return segments
}

export function planAndOffsetMap(
  index: PackedMatchIndex,
  entities: Entity[],
): { plan: ReplacementPlan; offsetMap: OffsetMap } {
  const plan = buildReplacementPlan(index, entities)
  return { plan, offsetMap: createOffsetMap(index, plan) }
}
