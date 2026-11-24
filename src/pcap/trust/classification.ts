/**
 * Enterprise step 1 — classifier vocabulary for SensitiveField / policy tables.
 * Parser emits these; policy (diagnostic | high-privacy) decides MAP/MASK/DROP/… (step 11).
 *
 * UNKNOWN_UNVERIFIED (not UNKNOWN_PLAINTEXT): we cannot always tell text vs binary vs
 * vendor format. ENCRYPTED_OPAQUE only from protocol state — never entropy heuristics.
 */

export const FIELD_CLASSIFICATIONS = [
  'IDENTITY',
  'SECRET',
  'MEDIA',
  'UNKNOWN_UNVERIFIED',
  'FINGERPRINT',
  'TIMING',
  'ENCRYPTED_OPAQUE',
  'SAFE_METADATA',
] as const

export type FieldClassification = (typeof FIELD_CLASSIFICATIONS)[number]

/** @deprecated Use UNKNOWN_UNVERIFIED — kept as alias for migration readability. */
export type LegacyUnknownPlaintext = 'UNKNOWN_PLAINTEXT'

export function isFieldClassification(value: unknown): value is FieldClassification {
  return (
    typeof value === 'string'
    && (FIELD_CLASSIFICATIONS as readonly string[]).includes(value)
  )
}

/**
 * Byte-range (or logical field) discovered by a protocol parser before policy apply.
 * Engine rewrite uses { start, length } relative to the packet / reassembled buffer.
 */
export interface SensitiveField {
  readonly type: string
  readonly start: number
  readonly length: number
  readonly classification: FieldClassification
}

/** Policy actions applied per classification (step 11 tables). */
export type PolicyAction =
  | 'MAP'
  | 'MASK'
  | 'DROP'
  | 'KEEP'
  | 'NORMALIZE'
  | 'RELATIVE'
  | 'ENUMERATE'
  | 'PRESERVE'
