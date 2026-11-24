import type { RawMatch, ResolvedMatch } from '../domain/types.ts'
import { entityKey } from './normalize.ts'

/**
 * Deterministic overlap resolution (ARCHITECTURE §7.2):
 * 1. higher priority
 * 2. longer match
 * 3. lower start
 * 4. detectorId / ruleId lexicographic
 */
export function compareRawMatches(a: RawMatch, b: RawMatch): number {
  if (a.priority !== b.priority) return b.priority - a.priority
  const lenA = a.end - a.start
  const lenB = b.end - b.start
  if (lenA !== lenB) return lenB - lenA
  if (a.start !== b.start) return a.start - b.start
  const idA = `${a.detectorId}/${a.ruleId ?? ''}`
  const idB = `${b.detectorId}/${b.ruleId ?? ''}`
  return idA < idB ? -1 : idA > idB ? 1 : 0
}

function overlaps(a: RawMatch, b: RawMatch): boolean {
  return a.start < b.end && b.start < a.end
}

/**
 * Greedy: sort by compareRawMatches, keep a match if it does not overlap any already kept.
 * Result is sorted by start ascending.
 *
 * Matches never span physical lines (detectOnPhysicalLine runs per line and remaps to
 * absolute offsets within that line's own range), so two matches on different lines can
 * never overlap. Resolving conflicts per line — instead of scanning every kept match in
 * the whole document for every candidate — turns this from O(totalMatches²) into roughly
 * O(totalMatches) for realistic per-line match counts, without changing the result.
 */
export function resolveOverlaps(raw: RawMatch[]): ResolvedMatch[] {
  const byLine = new Map<number, RawMatch[]>()
  for (const m of raw) {
    const bucket = byLine.get(m.line)
    if (bucket) bucket.push(m)
    else byLine.set(m.line, [m])
  }

  const kept: RawMatch[] = []
  for (const bucket of byLine.values()) {
    const ranked = bucket.length > 1 ? bucket.slice().sort(compareRawMatches) : bucket
    const keptOnLine: RawMatch[] = []
    for (const candidate of ranked) {
      let conflict = false
      for (const existing of keptOnLine) {
        if (overlaps(candidate, existing)) {
          conflict = true
          break
        }
      }
      if (!conflict) keptOnLine.push(candidate)
    }
    for (let i = 0; i < keptOnLine.length; i++) kept.push(keptOnLine[i]!)
  }

  kept.sort((a, b) => a.start - b.start || a.end - b.end)

  return kept.map((m) => ({
    ...m,
    entityKey: entityKey(m.category, m.normalized),
  }))
}
