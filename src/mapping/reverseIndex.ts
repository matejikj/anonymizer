/**
 * Reverse lookup index for mapping aliases and originals (Stage 19).
 */

import type { IdentityCategory } from './identityCategories'
import { identityMappingKey } from './canonicalize'
import type { AliasDisposition, OccurrenceRef } from './types'

export interface ReverseLookupCandidate {
  readonly identityId: number
  readonly category: IdentityCategory
  /** Null when plaintext was scrubbed after last occurrence removal. */
  readonly canonical: string | null
  readonly alias: string
  readonly fingerprint: string | null
  readonly disposition: AliasDisposition
  readonly occurrences: readonly OccurrenceRef[]
}

interface ReverseEntry {
  identityId: number
  category: IdentityCategory
  canonical: string | null
  primaryAlias: string
  fingerprint: string | null
  disposition: AliasDisposition
  scrubbed: boolean
}

export class ReverseIndex {
  private readonly byOriginal = new Map<string, Set<number>>()
  private readonly byAlias = new Map<string, Set<number>>()
  private readonly byFingerprint = new Map<string, number>()
  private readonly entries = new Map<number, ReverseEntry>()

  register(input: {
    identityId: number
    category: IdentityCategory
    canonical: string
    alias: string
    fingerprint: string
    disposition: AliasDisposition
  }): void {
    let entry = this.entries.get(input.identityId)
    if (!entry) {
      entry = {
        identityId: input.identityId,
        category: input.category,
        canonical: input.canonical,
        primaryAlias: input.alias,
        fingerprint: input.fingerprint,
        disposition: input.disposition,
        scrubbed: false,
      }
      this.entries.set(input.identityId, entry)
      this.indexOriginal(input.identityId, input.category, input.canonical)
      this.indexFingerprint(input.identityId, input.fingerprint)
    } else if (!entry.scrubbed && entry.canonical !== input.canonical) {
      this.unindexOriginal(entry.identityId, entry.category, entry.canonical!)
      entry.canonical = input.canonical
      this.indexOriginal(input.identityId, entry.category, input.canonical)
    }

    this.indexAlias(input.identityId, input.alias)
    entry.primaryAlias = input.alias
    entry.disposition = input.disposition
  }

  addAlias(identityId: number, alias: string): void {
    this.indexAlias(identityId, alias)
  }

  /** Remove plaintext from reverse lookup; fingerprint + reserved alias remain. */
  scrubPlaintext(identityId: number): void {
    const entry = this.entries.get(identityId)
    if (!entry || entry.scrubbed || entry.canonical === null) return
    this.unindexOriginal(identityId, entry.category, entry.canonical)
    entry.canonical = null
    entry.scrubbed = true
  }

  /** Restore plaintext after re-adding an occurrence of the same identity. */
  restorePlaintext(identityId: number, canonical: string): void {
    const entry = this.entries.get(identityId)
    if (!entry) return
    if (!entry.scrubbed && entry.canonical === canonical) return
    if (entry.canonical) {
      this.unindexOriginal(identityId, entry.category, entry.canonical)
    }
    entry.canonical = canonical
    entry.scrubbed = false
    this.indexOriginal(identityId, entry.category, canonical)
  }

  lookupByOriginal(
    category: IdentityCategory,
    canonical: string,
    occurrencesFor: (id: number) => readonly OccurrenceRef[],
  ): ReverseLookupCandidate[] {
    const key = identityMappingKey(category, canonical)
    const ids = this.byOriginal.get(key)
    if (!ids || ids.size === 0) return []
    return [...ids].map((id) => this.toCandidate(id, occurrencesFor(id)))
  }

  lookupByAlias(
    alias: string,
    occurrencesFor: (id: number) => readonly OccurrenceRef[],
  ): ReverseLookupCandidate[] {
    const ids = this.byAlias.get(alias)
    if (!ids || ids.size === 0) return []
    return [...ids].map((id) => this.toCandidate(id, occurrencesFor(id)))
  }

  lookupByFingerprint(
    fingerprint: string,
    occurrencesFor: (id: number) => readonly OccurrenceRef[],
  ): ReverseLookupCandidate | null {
    const id = this.byFingerprint.get(fingerprint)
    if (id === undefined) return null
    return this.toCandidate(id, occurrencesFor(id))
  }

  findIdentityId(category: IdentityCategory, canonical: string): number | undefined {
    const key = identityMappingKey(category, canonical)
    const ids = this.byOriginal.get(key)
    if (!ids || ids.size === 0) return undefined
    return [...ids][0]
  }

  getEntry(identityId: number): ReverseEntry | undefined {
    return this.entries.get(identityId)
  }

  clear(): void {
    this.byOriginal.clear()
    this.byAlias.clear()
    this.byFingerprint.clear()
    this.entries.clear()
  }

  private toCandidate(identityId: number, occurrences: readonly OccurrenceRef[]): ReverseLookupCandidate {
    const entry = this.entries.get(identityId)!
    return {
      identityId: entry.identityId,
      category: entry.category,
      canonical: entry.canonical,
      alias: entry.primaryAlias,
      fingerprint: entry.fingerprint,
      disposition: entry.disposition,
      occurrences,
    }
  }

  private indexOriginal(identityId: number, category: IdentityCategory, canonical: string): void {
    const key = identityMappingKey(category, canonical)
    let set = this.byOriginal.get(key)
    if (!set) {
      set = new Set()
      this.byOriginal.set(key, set)
    }
    set.add(identityId)
  }

  private unindexOriginal(identityId: number, category: IdentityCategory, canonical: string): void {
    const key = identityMappingKey(category, canonical)
    const set = this.byOriginal.get(key)
    if (!set) return
    set.delete(identityId)
    if (set.size === 0) this.byOriginal.delete(key)
  }

  private indexAlias(identityId: number, alias: string): void {
    let set = this.byAlias.get(alias)
    if (!set) {
      set = new Set()
      this.byAlias.set(alias, set)
    }
    set.add(identityId)
  }

  private indexFingerprint(identityId: number, fingerprint: string): void {
    this.byFingerprint.set(fingerprint, identityId)
  }
}
