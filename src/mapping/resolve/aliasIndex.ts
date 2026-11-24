/**
 * O(1) alias lookup index for resolve workspace (Stage 22).
 */

import type { MappingBundlePayload } from '../bundle/types'
import type { MappingSnapshot } from '../types'
import type { ResolveLookupCandidate } from './types'

export class AliasLookupIndex {
  private readonly byAlias = new Map<string, ResolveLookupCandidate[]>()
  private readonly uniqueAliases: string[] = []

  private constructor() {}

  static fromSnapshot(snapshot: MappingSnapshot): AliasLookupIndex {
    const idx = new AliasLookupIndex()
    for (const entry of snapshot.entries) {
      idx.add(entry.alias, {
        identityId: entry.identityId,
        category: entry.category,
        canonical: entry.canonical,
        alias: entry.alias,
        disposition: entry.disposition,
        occurrenceCount: entry.occurrenceCount,
      })
      for (const alt of entry.aliases) {
        if (alt.alias !== entry.alias) {
          idx.add(alt.alias, {
            identityId: entry.identityId,
            category: entry.category,
            canonical: entry.canonical,
            alias: alt.alias,
            disposition: alt.disposition,
            occurrenceCount: entry.occurrenceCount,
          })
        }
      }
    }
    idx.finalize()
    return idx
  }

  static fromBundlePayload(payload: MappingBundlePayload): AliasLookupIndex {
    const idx = new AliasLookupIndex()
    for (const entry of payload.entries) {
      idx.add(entry.alias, {
        identityId: entry.identityId,
        category: entry.category,
        canonical: entry.canonical,
        alias: entry.alias,
        disposition: entry.disposition,
        occurrenceCount: entry.occurrenceCount,
      })
    }
    idx.finalize()
    return idx
  }

  private add(alias: string, candidate: ResolveLookupCandidate): void {
    const list = this.byAlias.get(alias)
    if (list) {
      if (!list.some((c) => c.identityId === candidate.identityId && c.alias === candidate.alias)) {
        list.push(candidate)
      }
    } else {
      this.byAlias.set(alias, [candidate])
    }
  }

  private finalize(): void {
    this.uniqueAliases.push(...this.byAlias.keys())
    this.uniqueAliases.sort((a, b) => b.length - a.length)
  }

  lookupExact(alias: string): readonly ResolveLookupCandidate[] {
    return this.byAlias.get(alias) ?? []
  }

  allAliases(): readonly string[] {
    return this.uniqueAliases
  }

  get size(): number {
    return this.byAlias.size
  }
}
