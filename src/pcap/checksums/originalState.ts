/**
 * Enterprise step 6 — original checksum state sidecard (pre-sanitize).
 *
 * Transport checksums on capture may be invalid due to NIC offload; rewriting
 * them after sanitization is fine, but the original state must be recorded so
 * we never claim "output error came from input" without evidence.
 */

export const ORIGINAL_CHECKSUM_STATES = [
  'VALID',
  'INVALID',
  'OFFLOADED_PARTIAL',
  'NOT_PRESENT',
  'NOT_VERIFIABLE_TRUNCATED',
] as const

export type OriginalChecksumState = (typeof ORIGINAL_CHECKSUM_STATES)[number]

export function isOriginalChecksumState(value: unknown): value is OriginalChecksumState {
  return (
    typeof value === 'string'
    && (ORIGINAL_CHECKSUM_STATES as readonly string[]).includes(value)
  )
}

/**
 * Map engine disposition + verification hints onto the enterprise vocabulary.
 */
export function classifyOriginalChecksumState(input: {
  readonly present: boolean
  readonly truncated: boolean
  readonly verifiedValid: boolean | null
  /** UDP IPv4 zero checksum / Wireshark-style partial offload hint. */
  readonly offloadSuspected?: boolean
}): OriginalChecksumState {
  if (!input.present) return 'NOT_PRESENT'
  if (input.truncated) return 'NOT_VERIFIABLE_TRUNCATED'
  if (input.offloadSuspected) return 'OFFLOADED_PARTIAL'
  if (input.verifiedValid === true) return 'VALID'
  if (input.verifiedValid === false) return 'INVALID'
  return 'NOT_VERIFIABLE_TRUNCATED'
}
