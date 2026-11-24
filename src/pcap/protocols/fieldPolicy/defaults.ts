/**
 * T63.2 — fail-closed default field policy for handlers without a detailed table yet.
 * Any unknown field is masked in both levels (never silent preserve).
 */

import {
  assertFieldPolicyDictionary,
  DEFAULT_UNKNOWN_FIELD_POLICY,
  type FieldPolicyDescriptor,
} from '../../kernel/fieldPolicy'

/** Catch-all body/content policy — canary must vanish after export. */
export const DEFAULT_HANDLER_FIELD_POLICY: readonly FieldPolicyDescriptor[] = [
  {
    ...DEFAULT_UNKNOWN_FIELD_POLICY,
    fieldPath: 'payload',
    canaryKind: 'binary',
  },
  {
    variant: '*',
    fieldPath: '*',
    valueType: 'opaque',
    identityRole: 'content',
    diagnosticAction: 'mask',
    highPrivacyAction: 'mask',
    canaryKind: 'binary',
  },
]

assertFieldPolicyDictionary(DEFAULT_HANDLER_FIELD_POLICY)
