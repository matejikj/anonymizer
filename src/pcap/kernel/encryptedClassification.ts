/**
 * T14 — encrypted classification requires a documented confidentiality phase/variant.
 * Integrity, obfuscation, or port alone is not confidentiality (see T22/T28 contract).
 */

export const CONFIDENTIALITY_PHASES = [
  'handshake',
  'application-data',
  'key-exchange',
  'record-layer',
  'unknown',
] as const
export type ConfidentialityPhase = (typeof CONFIDENTIALITY_PHASES)[number]

export interface EncryptedClassification {
  readonly protocolId: string
  readonly variant: string
  readonly phase: ConfidentialityPhase
  /**
   * True only when the span is public-decodable ciphertext with a documented
   * confidentiality claim (e.g. TLS AppData after Finished). False for
   * obfuscation, MAC-only, or Initial packets with recoverable cleartext.
   */
  readonly confidentialityProven: boolean
}

export type EncryptedClassificationError =
  | { readonly code: 'missing-variant' }
  | { readonly code: 'missing-phase' }
  | { readonly code: 'confidentiality-unproven' }

/** Refuse `encrypted` disposition without phase + proven confidentiality variant. */
export function validateEncryptedClassification(
  input: EncryptedClassification,
): EncryptedClassificationError | null {
  if (!input.variant) return { code: 'missing-variant' }
  if (!CONFIDENTIALITY_PHASES.includes(input.phase)) return { code: 'missing-phase' }
  if (!input.confidentialityProven) return { code: 'confidentiality-unproven' }
  return null
}

export function assertEncryptedClassification(input: EncryptedClassification): void {
  const err = validateEncryptedClassification(input)
  if (!err) return
  throw new Error(`encrypted-classification:${err.code}:${input.protocolId}`)
}
