/**
 * Typed field policy dictionaries (T-01 stub → T14 / T63 descriptors).
 * Unknown fields default to mask; secret→preserve is a registration error.
 *
 * T63.2 — optional wire locators enable canary conformance: every non-preserve-safe
 * field can be overwritten with a unique canary and must be absent after export.
 */

import type { PrimaryDisposition } from './diagnosticImpact'
import type { WireEncoderKind } from './operations'

export type FieldIdentityRole =
  | 'none'
  | 'address'
  | 'name'
  | 'session'
  | 'device'
  | 'user'
  | 'secret'
  | 'content'

/** How a canary should be written into a synthetic frame for conformance. */
export type FieldCanaryKind = 'ascii' | 'binary' | 'none'

/**
 * Locate a field on the wire relative to a known protocol-header start offset.
 * `resolve` may return null when the frame is too short / variant-mismatched.
 */
export type FieldWireLocator =
  | {
      readonly kind: 'relative'
      readonly offset: number
      readonly length: number
    }
  | {
      readonly kind: 'resolve'
      readonly resolve: (
        frame: Uint8Array,
        protocolOffset: number,
      ) => { readonly offset: number; readonly length: number } | null
    }

/** Machine-checkable field descriptor — names from PROTOCOL-IMPLEMENTATION-CONTRACT §2.3. */
export interface FieldPolicyDescriptor {
  readonly variant: string
  readonly fieldPath: string
  readonly valueType: string
  readonly identityRole: FieldIdentityRole
  readonly identityScope?: string
  readonly wireEncoder?: WireEncoderKind
  readonly wireConstraintNote?: string
  readonly diagnosticAction: PrimaryDisposition
  readonly highPrivacyAction: PrimaryDisposition
  readonly preserveReason?: string
  readonly integrityDependency?: string
  /** T63.2 — wire span for canary injection (optional until locator is known). */
  readonly wire?: FieldWireLocator
  /** T63.2 — default binary; ascii for text fields; none skips injection. */
  readonly canaryKind?: FieldCanaryKind
}

/** @deprecated Prefer FieldPolicyDescriptor — kept as alias for existing imports. */
export type FieldPolicy = FieldPolicyDescriptor

/** Default for unknown / opaque content — never silent preserve. */
export const DEFAULT_UNKNOWN_FIELD_POLICY: FieldPolicyDescriptor = {
  variant: '*',
  fieldPath: '*',
  valueType: 'opaque',
  identityRole: 'content',
  diagnosticAction: 'mask',
  highPrivacyAction: 'mask',
}

export type FieldPolicyValidationError =
  | { readonly code: 'secret-preserve-forbidden'; readonly fieldPath: string }
  | { readonly code: 'unknown-preserve-without-reason'; readonly fieldPath: string }
  | { readonly code: 'encrypted-missing-phase'; readonly fieldPath: string }

/**
 * Validate a module field dictionary before registration.
 * Secret roles may never preserve; unknown preserve requires an explicit reason.
 */
export function validateFieldPolicyDictionary(
  policies: readonly FieldPolicyDescriptor[],
): readonly FieldPolicyValidationError[] {
  const errors: FieldPolicyValidationError[] = []
  for (const p of policies) {
    if (
      p.identityRole === 'secret'
      && (p.diagnosticAction === 'preserve' || p.highPrivacyAction === 'preserve')
    ) {
      errors.push({ code: 'secret-preserve-forbidden', fieldPath: p.fieldPath })
    }
    if (
      (p.diagnosticAction === 'preserve' || p.highPrivacyAction === 'preserve')
      && p.fieldPath === '*'
      && !p.preserveReason
    ) {
      errors.push({ code: 'unknown-preserve-without-reason', fieldPath: p.fieldPath })
    }
    if (
      (p.diagnosticAction === 'encrypted' || p.highPrivacyAction === 'encrypted')
      && !p.variant
    ) {
      errors.push({ code: 'encrypted-missing-phase', fieldPath: p.fieldPath })
    }
  }
  return errors
}

/** Throw when dictionary registration would allow secret preserve / silent unknown preserve. */
export function assertFieldPolicyDictionary(
  policies: readonly FieldPolicyDescriptor[],
): void {
  const errors = validateFieldPolicyDictionary(policies)
  if (errors.length === 0) return
  const first = errors[0]!
  throw new Error(`field-policy-registration:${first.code}:${first.fieldPath}`)
}

/**
 * True when the field is identity-free preserve for the given level.
 * Without a level, both levels must preserve (strict canary skip).
 */
export function fieldPolicyAllowsPreserveSafe(
  policy: FieldPolicyDescriptor,
  level?: 'diagnostic' | 'high-privacy',
): boolean {
  if (policy.identityRole !== 'none') return false
  if (level === 'diagnostic') return policy.diagnosticAction === 'preserve'
  if (level === 'high-privacy') return policy.highPrivacyAction === 'preserve'
  return policy.diagnosticAction === 'preserve' && policy.highPrivacyAction === 'preserve'
}

/**
 * Fields that must not retain a canary after export for the given level
 * (everything except proven preserve-safe / proven ciphertext).
 */
export function fieldPolicyRequiresCanaryAbsence(
  policy: FieldPolicyDescriptor,
  level?: 'diagnostic' | 'high-privacy',
): boolean {
  if (policy.canaryKind === 'none') return false
  if (fieldPolicyAllowsPreserveSafe(policy, level)) return false
  const action =
    level === 'high-privacy' ? policy.highPrivacyAction : policy.diagnosticAction
  if (action === 'encrypted') return false
  return true
}

/** Resolve absolute packet offsets for a field, or null when not locatable. */
export function resolveFieldWireSpan(
  policy: FieldPolicyDescriptor,
  frame: Uint8Array,
  protocolOffset: number,
): { readonly offset: number; readonly length: number } | null {
  const wire = policy.wire
  if (!wire) return null
  if (wire.kind === 'relative') {
    const offset = protocolOffset + wire.offset
    if (offset < 0 || wire.length <= 0 || offset + wire.length > frame.length) return null
    return { offset, length: wire.length }
  }
  return wire.resolve(frame, protocolOffset)
}
