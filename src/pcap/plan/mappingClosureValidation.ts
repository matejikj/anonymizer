/**
 * Mapping closure validation — every entity-replacement intent must resolve
 * against the immutable MappingSnapshot before plan build / export (step 2).
 */

import { mappingKey, type CanonicalIdentity, type MappingSnapshot, type WireRepresentationConstraint } from '../../mapping/types'
import { constraintKey } from '../../mapping/constraintKey'
import { aliasForSnapshotConstraintStrict } from '../../mapping/mappingRegistry'
import type { TransformationIntent } from '../discovery/types'
import { PlanInvariantError } from './planErrors'
import { indexSnapshotEntriesByMappingKey } from './snapshotEntryIndex'

export type MappingClosureFailureReason = 'missing-snapshot-entry' | 'missing-constraint-alias'

export interface MappingClosureFailure {
  readonly packetIndex: number
  readonly category: string
  readonly canonical: string
  readonly constraint: WireRepresentationConstraint
  readonly originalSpelling?: string
  readonly reason: MappingClosureFailureReason
}

export type MappingClosureValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly failures: readonly MappingClosureFailure[] }

/**
 * Validate that every entity-replacement intent has a snapshot entry with a
 * compatible alias for its wire constraint.
 */
export function validateMappingClosure(
  intents: readonly TransformationIntent[],
  snapshot: MappingSnapshot,
): MappingClosureValidationResult {
  const entries = indexSnapshotEntriesByMappingKey(snapshot)
  const failures: MappingClosureFailure[] = []
  const seen = new Set<string>()

  for (const intent of intents) {
    if (intent.kind !== 'entity-replacement') continue
    const sig = [
      intent.packetIndex,
      intent.category,
      intent.canonical,
      constraintKey(intent.constraint),
      intent.originalSpelling ?? '',
    ].join('|')
    if (seen.has(sig)) continue
    seen.add(sig)

    const entry = entries.get(mappingKey(intent.category, intent.canonical))
    if (!entry) {
      if (snapshot.overflow) continue
      failures.push({
        packetIndex: intent.packetIndex,
        category: intent.category,
        canonical: intent.canonical,
        constraint: intent.constraint,
        originalSpelling: intent.originalSpelling,
        reason: 'missing-snapshot-entry',
      })
      continue
    }

    const alias = aliasForSnapshotConstraintStrict(entry, intent.constraint)
    if (alias === undefined) {
      failures.push({
        packetIndex: intent.packetIndex,
        category: intent.category,
        canonical: intent.canonical,
        constraint: intent.constraint,
        originalSpelling: intent.originalSpelling,
        reason: 'missing-constraint-alias',
      })
    }
  }

  return failures.length === 0 ? { ok: true } : { ok: false, failures }
}

/** Identities needed to satisfy closure failures (for one automatic top-up resolve). */
export function identitiesForClosureFailures(
  failures: readonly MappingClosureFailure[],
): CanonicalIdentity[] {
  const seen = new Set<string>()
  const out: CanonicalIdentity[] = []
  for (const f of failures) {
    const key = `${f.category}:${f.canonical}:${constraintKey(f.constraint)}:${f.originalSpelling ?? ''}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({
      category: f.category as CanonicalIdentity['category'],
      canonical: f.canonical,
      constraint: f.constraint,
      originalSpelling: f.originalSpelling,
      occurrence: { kind: 'packet', sourceId: 'closure-topup', packetIndex: f.packetIndex },
    })
  }
  return out
}

/**
 * @deprecated T04 — production soft-fails via {@link resolveSnapshotWithMappingClosure}.
 * Kept for tests that explicitly assert the hard-fail shape.
 */
export function throwMappingClosureFailure(
  failures: readonly MappingClosureFailure[],
  packetNumberForIndex?: (packetIndex: number) => number | undefined,
): never {
  const f = failures[0]
  if (!f) {
    throw new PlanInvariantError({
      code: 'mapping-closure',
      message: 'Mapping closure validation failed without details',
    })
  }
  const packetNumber = packetNumberForIndex?.(f.packetIndex)
  throw new PlanInvariantError({
    code: 'mapping-closure',
    message:
      `Missing mapping alias for category=${f.category} `
      + `(reason ${f.reason})`
      + ` at packetIndex=${f.packetIndex}`
      + (packetNumber !== undefined ? ` packetNumber=${packetNumber}` : ''),
    packetIndex: f.packetIndex,
    packetNumber,
    category: f.category,
    // Intentionally omit canonical from the thrown message path used by UI.
    constraint: f.constraint,
    causeCode: f.reason,
  })
}

export interface MappingClosureResolveResult {
  readonly snapshot: MappingSnapshot
  /** Failures remaining after one top-up — plan path fail-closes fields + records incidents. */
  readonly unresolvedFailures: readonly MappingClosureFailure[]
}

/**
 * Resolve snapshot, validate closure, top-up missing identities once, re-validate.
 * T04: remaining failures soft-fail — returned for incident/field-fallback, not thrown.
 */
export async function resolveSnapshotWithMappingClosure(input: {
  readonly generationId: string
  readonly sourceId: string
  readonly identities: readonly CanonicalIdentity[]
  readonly intents: readonly TransformationIntent[]
  readonly resolve: (identities: readonly CanonicalIdentity[]) => Promise<MappingSnapshot>
  readonly packetNumberForIndex?: (packetIndex: number) => number | undefined
}): Promise<MappingClosureResolveResult> {
  void input.packetNumberForIndex
  let snapshot = await input.resolve(input.identities)
  let validation = validateMappingClosure(input.intents, snapshot)
  if (validation.ok) return { snapshot, unresolvedFailures: [] }

  const topUp = identitiesForClosureFailures(validation.failures)
  const merged = dedupeIdentities([...input.identities, ...topUp])
  snapshot = await input.resolve(merged)
  validation = validateMappingClosure(input.intents, snapshot)
  if (!validation.ok) {
    return { snapshot, unresolvedFailures: validation.failures }
  }
  return { snapshot, unresolvedFailures: [] }
}

export function dedupeIdentities(identities: readonly CanonicalIdentity[]): CanonicalIdentity[] {
  const seen = new Set<string>()
  const out: CanonicalIdentity[] = []
  for (const id of identities) {
    const key = `${id.category}:${id.canonical}:${constraintKey(id.constraint)}:${id.originalSpelling ?? ''}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(id)
  }
  return out
}
