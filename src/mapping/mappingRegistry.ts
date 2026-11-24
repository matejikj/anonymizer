/**
 * Append-only mapping registry with identity graph (Stage 18 / Stage 19).
 */

import { MAPPING_CAPABILITY_LIMITS } from '../domain/capabilityContract'
import type { IdentityCategory } from './identityCategories'
import { identityMappingKey } from './canonicalize'
import type {
  AliasDisposition,
  IdentitySourceRef,
  MappingRegistryEntry,
  OccurrenceRef,
  RepresentationAlias,
  WireRepresentationConstraint,
} from './types'
import { constraintKey as wireConstraintKey } from './constraintKey'

export class MappingRegistry {
  private readonly _entries = new Map<number, MappingRegistryEntry>()
  private readonly _keyToId = new Map<string, number>()
  private _nextId = 1

  get size(): number {
    return this._entries.size
  }

  getEntry(identityId: number): MappingRegistryEntry | undefined {
    return this._entries.get(identityId)
  }

  findByKey(category: IdentityCategory, canonical: string): MappingRegistryEntry | undefined {
    const id = this._keyToId.get(identityMappingKey(category, canonical))
    return id !== undefined ? this._entries.get(id) : undefined
  }

  findByRegistryKey(registryKey: string): MappingRegistryEntry | undefined {
    const id = this._keyToId.get(registryKey)
    return id !== undefined ? this._entries.get(id) : undefined
  }

  findById(identityId: number): MappingRegistryEntry | undefined {
    return this._entries.get(identityId)
  }

  /** Append-only: register or extend an identity. Never removes or recycles aliases. */
  register(input: {
    category: IdentityCategory
    canonical: string
    alias: string
    constraint: WireRepresentationConstraint
    disposition: AliasDisposition
    source: IdentitySourceRef
    originalSample?: string
    occurrence?: OccurrenceRef
    fingerprint: string
    registryKey?: string
  }): { entry: MappingRegistryEntry; aliasAdded: boolean; aliasRejected: boolean } {
    const key = input.registryKey ?? identityMappingKey(input.category, input.canonical)
    let entry = this.findByRegistryKey(key) ?? this.findByKey(input.category, input.canonical)
    let aliasAdded = false
    let aliasRejected = false

    if (!entry) {
      const identityId = this._nextId++
      entry = {
        identityId,
        category: input.category,
        canonical: input.canonical,
        originalSample: input.originalSample ?? input.canonical,
        aliases: [],
        source: input.source,
        occurrenceCount: 0,
        occurrences: [],
        primaryDisposition: input.disposition,
        fingerprint: input.fingerprint,
        plaintextActive: true,
      }
      this._entries.set(identityId, entry)
      this._keyToId.set(key, identityId)
    }

    const addResult = this.addAlias(entry, input.alias, input.constraint, input.disposition)
    aliasAdded = addResult.added
    aliasRejected = addResult.rejected

    if (input.occurrence) {
      entry.occurrenceCount++
      if (entry.occurrences.length < 64) {
        entry.occurrences.push(input.occurrence)
      }
    } else {
      entry.occurrenceCount++
    }

    if (input.originalSample && entry.originalSample === entry.canonical) {
      entry.originalSample = input.originalSample
    }

    if (!entry.plaintextActive) {
      entry.plaintextActive = true
    }

    return { entry, aliasAdded, aliasRejected }
  }

  markPlaintextScrubbed(identityId: number): void {
    const entry = this._entries.get(identityId)
    if (!entry) return
    entry.plaintextActive = false
  }

  restorePlaintext(identityId: number): void {
    const entry = this._entries.get(identityId)
    if (!entry) return
    entry.plaintextActive = true
  }

  entries(): readonly MappingRegistryEntry[] {
    return [...this._entries.values()]
  }

  clear(): void {
    this._entries.clear()
    this._keyToId.clear()
    this._nextId = 1
  }

  private addAlias(
    entry: MappingRegistryEntry,
    alias: string,
    constraint: WireRepresentationConstraint,
    disposition: AliasDisposition,
  ): { added: boolean; rejected: boolean } {
    const existing = entry.aliases.find(
      (a) => a.alias === alias && wireConstraintKey(a.constraint) === wireConstraintKey(constraint),
    )
    if (existing) return { added: false, rejected: false }

    if (entry.aliases.length >= MAPPING_CAPABILITY_LIMITS.maxAliasesPerIdentity) {
      return { added: false, rejected: true }
    }

    const rep: RepresentationAlias = Object.freeze({
      alias,
      constraint,
      disposition,
    })
    entry.aliases.push(rep)
    return { added: true, rejected: false }
  }
}

export function primaryAlias(entry: MappingRegistryEntry): string {
  return entry.aliases[0]?.alias ?? entry.canonical
}

export function aliasForConstraint(
  entry: MappingRegistryEntry,
  constraint: WireRepresentationConstraint,
): string {
  const key = wireConstraintKey(constraint)
  for (const a of entry.aliases) {
    if (wireConstraintKey(a.constraint) === key) return a.alias
  }
  return entry.aliases[0]?.alias ?? entry.canonical
}

/** Strict constraint lookup — undefined when no alias matches (CF-02). */
export function aliasForSnapshotConstraintStrict(
  entry: { readonly aliases: readonly RepresentationAlias[] },
  constraint: WireRepresentationConstraint,
): string | undefined {
  const key = wireConstraintKey(constraint)
  for (const a of entry.aliases) {
    if (wireConstraintKey(a.constraint) === key) return a.alias
  }
  return undefined
}

/** Resolve a constraint-specific alias from a snapshot entry (legacy fallback — prefer strict + adapter). */
export function aliasForSnapshotConstraint(
  entry: { readonly alias: string; readonly aliases: readonly RepresentationAlias[]; readonly canonical: string },
  constraint: WireRepresentationConstraint,
): string {
  return aliasForSnapshotConstraintStrict(entry, constraint) ?? (entry.alias || entry.canonical)
}

export function reservedAlias(entry: MappingRegistryEntry): string {
  return entry.aliases[0]?.alias ?? entry.canonical
}
