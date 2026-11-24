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
import {
  createTextReplacementCounters,
  generateFreeTokenAlias,
  maskAlphanumeric,
} from '../mapping/textAliasEngine.ts'

export interface ReplacementPlan {
  /**
   * Parallel to PackedMatchIndex rows: replacement string.
   * T71 / D4 — disabled category aliases still get a free-token (never null / original).
   */
  replacements: Array<string | null>
  /** length(replacement) - length(original) per match; 0 if disabled. */
  lengthDeltas: Int32Array
  fenwick: Int32Array
  /** T71 — matches that used free-token because category/entity alias was suppressed. */
  readonly aliasSuppressedCount?: number
}

/** Length-stable free-token when the user suppresses a category alias (D4). */
function freeTokenForDisabledEntity(
  entity: Entity,
  matchLen: number,
  cache: Map<string, string>,
  counters: ReturnType<typeof createTextReplacementCounters>,
): string {
  const len = Math.max(1, matchLen)
  let base = cache.get(entity.key)
  if (!base) {
    const sample =
      entity.originalSample.length > 0
        ? entity.originalSample
        : entity.normalized.length > 0
          ? entity.normalized
          : 'x'.repeat(len)
    base = generateFreeTokenAlias(sample, counters)
    cache.set(entity.key, base)
  }
  if (base.length === len) return base
  const shape = entity.originalSample.length === len
    ? entity.originalSample
    : 'x'.repeat(len)
  return maskAlphanumeric(shape, base)
}

export function buildReplacementPlan(
  index: PackedMatchIndex,
  entities: Entity[],
): ReplacementPlan {
  const n = index.starts.length
  const replacements: Array<string | null> = new Array(n)
  const lengthDeltas = new Int32Array(n)
  const cache = new Map<string, string>()
  const counters = createTextReplacementCounters()
  let aliasSuppressedCount = 0
  for (let i = 0; i < n; i++) {
    const useCategoryAlias = (index.flags[i]! & FLAG_ENABLED) !== 0
    const entity = entities[index.entityIndexes[i]!]
    const matchLen = index.lengths[i]!
    if (!entity) {
      // Fail-closed: never leave a detector span as original.
      const fill = 'x'.repeat(Math.max(1, matchLen))
      replacements[i] = fill
      lengthDeltas[i] = fill.length - matchLen
      aliasSuppressedCount += 1
      continue
    }
    if (useCategoryAlias) {
      assertNoNewline(entity.replacement, 'replacement')
      replacements[i] = entity.replacement
      lengthDeltas[i] = entity.replacement.length - matchLen
      continue
    }
    // T71 / D4 — alias suppressed → free-token pseudonym (never original).
    const fallback = freeTokenForDisabledEntity(entity, matchLen, cache, counters)
    assertNoNewline(fallback, 'free-token-fallback')
    replacements[i] = fallback
    lengthDeltas[i] = fallback.length - matchLen
    aliasSuppressedCount += 1
  }
  return {
    replacements,
    lengthDeltas,
    fenwick: fenwickBuild(lengthDeltas),
    aliasSuppressedCount,
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
  const cache = new Map<string, string>()
  const counters = createTextReplacementCounters()
  for (const m of matches) {
    const entity = entitiesByKey.get(m.entityKey)
    if (!entity) continue
    const matchLen = m.end - m.start
    const replacement = entity.enabled
      ? entity.replacement
      : freeTokenForDisabledEntity(entity, matchLen, cache, counters)
    assertNoNewline(replacement, 'replacement')
    if (m.start > cursor) parts.push(original.slice(cursor, m.start))
    parts.push(replacement)
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
  const cache = new Map<string, string>()
  const counters = createTextReplacementCounters()
  for (const m of matches) {
    const entity = entitiesByKey.get(m.entityKey)
    if (!entity) continue
    const matchLen = m.end - m.start
    const rep = entity.enabled
      ? entity.replacement
      : freeTokenForDisabledEntity(entity, matchLen, cache, counters)
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
