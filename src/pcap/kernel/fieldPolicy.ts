/**
 * Typed field policy dictionaries (T-01 stub → T14 descriptors).
 * Unknown fields default to mask; secret→preserve is a registration error.
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

/** Machine-checkable field descriptor — names from PROTOCOL-IMPLEMENTATION-CONTRACT. */
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
