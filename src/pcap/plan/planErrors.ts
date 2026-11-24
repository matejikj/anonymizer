/**
 * Plan-time invariant vs packet parse failures (diagnostic anonymization step 2).
 */

import type { WireRepresentationConstraint } from '../../mapping/types'
import { MappingLookupError, MappingPatchError } from '../anonymization/mappingErrors'

export type PlanInvariantCode =
  | 'mapping-closure'
  | 'patch-overlap'
  | 'mapping-lookup'
  | 'representation-unavailable'
  | 'unsafe-export-boundary'

export interface PlanInvariantDetails {
  readonly code: PlanInvariantCode
  readonly message: string
  readonly packetIndex?: number
  readonly packetNumber?: number
  readonly category?: string
  readonly canonical?: string
  readonly constraint?: WireRepresentationConstraint
  readonly causeCode?: string
}

/** Fail-closed plan/export error — must not be converted into a silent packet drop. */
export class PlanInvariantError extends Error {
  readonly code: PlanInvariantCode
  readonly packetIndex?: number
  readonly packetNumber?: number
  readonly category?: string
  readonly canonical?: string
  readonly constraint?: WireRepresentationConstraint
  readonly causeCode?: string

  constructor(details: PlanInvariantDetails) {
    super(details.message)
    this.name = 'PlanInvariantError'
    this.code = details.code
    this.packetIndex = details.packetIndex
    this.packetNumber = details.packetNumber
    this.category = details.category
    this.canonical = details.canonical
    this.constraint = details.constraint
    this.causeCode = details.causeCode
  }
}

/**
 * Step 9 — safe plan-error reason code for UI (no original entity values).
 */
export function planInvariantSafeReasonCode(
  error: PlanInvariantError,
): 'closure' | 'lookup' | 'patch' | 'boundary' | 'generic' {
  switch (error.code) {
    case 'mapping-closure':
      return 'closure'
    case 'mapping-lookup':
    case 'representation-unavailable':
      return 'lookup'
    case 'patch-overlap':
      return 'patch'
    case 'unsafe-export-boundary':
      return 'boundary'
    default:
      return 'generic'
  }
}

/** True decoder/parser failure for a single packet (may follow malformedPayloadPolicy). */
export class PacketParseError extends Error {
  readonly packetIndex: number

  constructor(packetIndex: number, message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'PacketParseError'
    this.packetIndex = packetIndex
  }
}

export function isPlanBlockingError(error: unknown): error is PlanInvariantError | MappingLookupError | MappingPatchError {
  return (
    error instanceof PlanInvariantError
    || error instanceof MappingLookupError
    || error instanceof MappingPatchError
  )
}

export function toPlanInvariantError(
  error: unknown,
  packetIndex?: number,
): PlanInvariantError {
  if (error instanceof PlanInvariantError) return error
  if (error instanceof MappingLookupError) {
    return new PlanInvariantError({
      code: error.code === 'representation-unavailable' ? 'representation-unavailable' : 'mapping-lookup',
      // T03: structured fields only — never forward value-bearing messages.
      message: `Mapping lookup failed (category=${error.category ?? 'unknown'}, reason=${error.code})`,
      packetIndex,
      category: error.category,
      causeCode: error.code,
    })
  }
  if (error instanceof MappingPatchError) {
    return new PlanInvariantError({
      code: 'patch-overlap',
      message: `Mapping patch failed (reason=${error.code})`,
      packetIndex,
      causeCode: error.code,
    })
  }
  return new PlanInvariantError({
    code: 'mapping-closure',
    message: 'Plan invariant failed (reason=unknown)',
    packetIndex,
  })
}
