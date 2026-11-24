/**
 * Session-scoped interning for identity strings and wire constraints.
 *
 * Every packet of a flow re-derives the same canonical identities (`10.1.2.3`, `udp/5060`, …)
 * and the same constraint shapes (`{ kind: 'ipv4-wire' }`); retained per op/intent for 200k+
 * packets that is hundreds of MiB of identical strings and objects. Interned values are equal
 * to the input, so behaviour never changes — only duplicate copies disappear.
 *
 * Interning is active only inside a capture processing / discovery run (openIdentityInternScope);
 * outside one (plan build, main thread, unit tests) every function returns its input unchanged.
 * The pool is cleared when the first scope opens and when the last one closes — also on error or
 * cancel (callers close in `finally`) — and is bounded, so it never holds identity strings or
 * lookup keys beyond the runs that created them. Interned values stay shared via their references.
 */

import { constraintKey } from '../../mapping/constraintKey'
import type { WireRepresentationConstraint } from '../../mapping/types'
import { MAX_ENTITY_CARDINALITY } from '../../domain/capabilityContract'
import type { LayerCoverage } from '../sanitize/types'
import type { SymbolicOperation } from './operations'

/** Distinct identities are capped at MAX_ENTITY_CARDINALITY; spellings add a few per identity. */
const MAX_INTERNED_STRINGS = MAX_ENTITY_CARDINALITY * 2
const MAX_INTERNED_CONSTRAINTS = 4_096
/** Per-packet coverage / issue lists repeat per flow shape (RTP, SIP, …), not per packet. */
const MAX_INTERNED_LISTS = 50_000

const strings = new Map<string, string>()
const constraints = new Map<string, WireRepresentationConstraint>()
const coverageLists = new Map<string, readonly LayerCoverage[]>()
const issueLists = new Map<string, readonly string[]>()
const sharedOps = new Map<string, SymbolicOperation>()
/** Distinct (field, offset, identity) ops per session — bounded like identities. */
const MAX_SHARED_OPS = MAX_ENTITY_CARDINALITY
/** Open run scopes; >1 only when a worker overlaps runs (a superseded run still finishing). */
let openScopes = 0
const EMPTY_COVERAGE: readonly LayerCoverage[] = []
const EMPTY_ISSUES: readonly string[] = []

export function internString(value: string): string
export function internString(value: string | undefined): string | undefined
export function internString(value: string | undefined): string | undefined {
  if (value === undefined || openScopes === 0) return value
  const hit = strings.get(value)
  if (hit !== undefined) return hit
  if (strings.size < MAX_INTERNED_STRINGS) strings.set(value, value)
  return value
}

export function internConstraint<T extends WireRepresentationConstraint>(constraint: T): T
export function internConstraint<T extends WireRepresentationConstraint>(constraint: T | undefined): T | undefined
export function internConstraint<T extends WireRepresentationConstraint>(constraint: T | undefined): T | undefined {
  if (constraint === undefined || openScopes === 0) return constraint
  const key = constraintKey(constraint)
  // Unknown kind at runtime (e.g. decoded from a wire payload) — never merge it with others.
  if (typeof key !== 'string') return constraint
  const hit = constraints.get(key)
  if (hit !== undefined) return hit as T
  if (constraints.size < MAX_INTERNED_CONSTRAINTS) constraints.set(key, constraint)
  return constraint
}

/**
 * Share identical per-packet coverage lists. Lists are final once a packet is frozen (sanitizers
 * only push while building them; later steps such as reassembly overlays or CoAP finalisation
 * create new arrays), so sharing is safe. The key is the full JSON of the rows, so two lists are
 * merged only when every field of every row is equal.
 */
export function internCoverage(rows: readonly LayerCoverage[]): readonly LayerCoverage[] {
  if (rows.length === 0) return EMPTY_COVERAGE
  if (openScopes === 0) return rows
  const key = JSON.stringify(rows)
  const hit = coverageLists.get(key)
  if (hit !== undefined) return hit
  if (coverageLists.size < MAX_INTERNED_LISTS) coverageLists.set(key, rows)
  return rows
}

/** Share identical per-packet issue-token lists (same finality argument as coverage). */
export function internIssues(issues: readonly string[]): readonly string[] {
  if (issues.length === 0) return EMPTY_ISSUES
  if (openScopes === 0) return issues
  const key = issues.join('\u0001')
  const hit = issueLists.get(key)
  if (hit !== undefined) return hit
  if (issueLists.size < MAX_INTERNED_LISTS) issueLists.set(key, issues)
  return issues
}

/**
 * Key over every field except `packetIndex` for ops whose rendered bytes do not depend on the
 * packet beyond that index (renderer takes the index from the plan — see RenderContext).
 * Fingerprint (carries per-packet original values), fixed, checksum and session-version ops
 * are never shared.
 */
function sharedOpKey(op: SymbolicOperation): string | null {
  // JSON arrays: canonicals / spellings may contain any character, so no separator is safe.
  switch (op.kind) {
    case 'map': {
      const constraint = constraintKey(op.constraint)
      // Unknown constraint kind — never merge it with others (see internConstraint).
      if (typeof constraint !== 'string') return null
      return JSON.stringify([op.kind, op.offset, op.length, op.category, op.canonical, constraint, op.encoder, op.originalSpelling ?? null])
    }
    case 'mask':
      return JSON.stringify([op.kind, op.offset, op.length, op.fillKind, op.domain, op.reasonCode])
    case 'secret':
    case 'preserve':
      return JSON.stringify([op.kind, op.offset, op.length, op.reasonCode])
    default:
      return null
  }
}

/**
 * Share an op created for `packetIndex` with identical ops of other packets (same flow shape:
 * same offsets, identities and fill domains). Only ops that belong to this packet are shared.
 */
export function internSharedOp(op: SymbolicOperation, packetIndex: number): SymbolicOperation {
  if (op.packetIndex !== packetIndex || openScopes === 0) return op
  const key = sharedOpKey(op)
  if (key === null) return op
  const hit = sharedOps.get(key)
  if (hit !== undefined) return hit
  if (sharedOps.size < MAX_SHARED_OPS) sharedOps.set(key, op)
  return op
}

export interface IdentityInternScope {
  /** Idempotent; call once the run stops creating plans and again in `finally`. */
  close(): void
}

/** Start of a capture run. */
export function openIdentityInternScope(): IdentityInternScope {
  if (openScopes === 0) clearPools()
  openScopes++
  let open = true
  return {
    close() {
      if (!open) return
      open = false
      openScopes--
      if (openScopes === 0) clearPools()
    },
  }
}

function clearPools(): void {
  strings.clear()
  constraints.clear()
  coverageLists.clear()
  issueLists.clear()
  sharedOps.clear()
}
