/**
 * CF-02 / T03 — explicit mapping lookup failures (no silent canonical fallback).
 * Error messages must never include original/canonical identity values.
 */

export type MappingLookupErrorCode =
  | 'missing-snapshot-alias'
  | 'representation-unavailable'
  | 'length-mismatch'
  | 'canonicalize-failed'
  | 'missing-wire-constraint';

export class MappingLookupError extends Error {
  readonly code: MappingLookupErrorCode
  /** Identity category only — never the value. */
  readonly category?: string

  constructor(
    code: MappingLookupErrorCode,
    options?: { readonly category?: string; readonly message?: string },
  ) {
    const category = options?.category
    const message = options?.message
      ?? (category
        ? `Mapping lookup failed (category=${category}, reason=${code})`
        : `Mapping lookup failed (reason=${code})`)
    super(message)
    this.name = 'MappingLookupError'
    this.code = code
    this.category = category
  }
}

export class MappingPatchError extends Error {
  readonly code: 'length-mismatch' | 'patch-overlap'

  constructor(code: 'length-mismatch' | 'patch-overlap', message?: string) {
    super(message ?? `Mapping patch failed (reason=${code})`)
    this.name = 'MappingPatchError'
    this.code = code
  }
}
