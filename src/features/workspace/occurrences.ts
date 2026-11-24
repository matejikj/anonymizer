/**
 * Occurrence list + navigation across packed matches (ARCHITECTURE §3.3 / Krok 5).
 */

import type { PackedMatchIndex } from '../../domain/types.ts'
import type { EntitySummary } from '../../domain/types.ts'
import { getSessionModel } from './sessionModel.ts'

export interface Occurrence {
  matchIndex: number
  entityKey: string
  category: string
  start: number
  end: number
  line: number
  replacement: string | null
}

export function listOccurrences(
  packed: PackedMatchIndex,
  entities: EntitySummary[],
  replacements: Array<string | null>,
): Occurrence[] {
  const out: Occurrence[] = []
  for (let i = 0; i < packed.starts.length; i++) {
    const ent = entities[packed.entityIndexes[i]!]
    if (!ent) continue
    out.push({
      matchIndex: i,
      entityKey: ent.key,
      category: ent.category,
      start: packed.starts[i]!,
      end: packed.starts[i]! + packed.lengths[i]!,
      line: packed.lines[i]!,
      replacement: replacements[i] ?? null,
    })
  }
  return out
}

export function occurrencesFromSession(): Occurrence[] {
  const session = getSessionModel()
  if (!session) return []
  return listOccurrences(session.packed, session.entitySummaries, session.plan.replacements)
}

/** Next/prev index into the occurrences array (wraps). */
export function stepOccurrenceIndex(
  current: number,
  delta: number,
  total: number,
): number {
  if (total <= 0) return -1
  if (current < 0) return delta > 0 ? 0 : total - 1
  return (current + delta + total * 1000) % total
}
