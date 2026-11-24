/**
 * Index MappingSnapshot entries by category:canonical, merging aliases when
 * cross-format registry keys produce duplicate snapshot rows for one identity.
 */

import { mappingKey, type MappingSnapshot, type RepresentationAlias } from '../../mapping/types'
import { constraintKey } from '../../mapping/constraintKey'

export type MergedSnapshotEntry = MappingSnapshot['entries'][number] & {
  readonly aliases: readonly RepresentationAlias[]
}

export function indexSnapshotEntriesByMappingKey(
  snapshot: MappingSnapshot,
): Map<string, MergedSnapshotEntry> {
  const out = new Map<string, MergedSnapshotEntry>()
  for (const entry of snapshot.entries) {
    const key = mappingKey(entry.category, entry.canonical)
    const existing = out.get(key)
    if (!existing) {
      out.set(key, entry)
      continue
    }
    out.set(key, mergeSnapshotEntries(existing, entry))
  }
  return out
}

function mergeSnapshotEntries(
  a: MergedSnapshotEntry,
  b: MergedSnapshotEntry,
): MergedSnapshotEntry {
  const seen = new Set(a.aliases.map((x) => constraintKey(x.constraint)))
  const aliases = [...a.aliases]
  for (const alias of b.aliases) {
    const ck = constraintKey(alias.constraint)
    if (seen.has(ck)) continue
    seen.add(ck)
    aliases.push(alias)
  }
  return {
    ...a,
    aliases: Object.freeze(aliases),
    occurrenceCount: Math.max(a.occurrenceCount, b.occurrenceCount),
  }
}
