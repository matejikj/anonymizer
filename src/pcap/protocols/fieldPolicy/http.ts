/**
 * T63.2 — HTTP field policy table (re-exports T14 dictionary + canary metadata).
 */

import { HTTP_FIELD_DICTIONARY } from '../../kernel/httpFieldDictionary'
import {
  assertFieldPolicyDictionary,
  type FieldPolicyDescriptor,
} from '../../kernel/fieldPolicy'

function withCanary(policy: FieldPolicyDescriptor): FieldPolicyDescriptor {
  if (policy.canaryKind !== undefined) return policy
  const ascii =
    policy.valueType.includes('ascii')
    || policy.valueType.includes('authority')
    || policy.valueType.includes('http-date')
    || policy.fieldPath.startsWith('header.')
  return {
    ...policy,
    canaryKind: ascii ? 'ascii' : 'binary',
  }
}

export const HTTP_HANDLER_FIELD_POLICY: readonly FieldPolicyDescriptor[] =
  HTTP_FIELD_DICTIONARY.map(withCanary)

assertFieldPolicyDictionary(HTTP_HANDLER_FIELD_POLICY)
