/**
 * T63.2 — DNS/mDNS baseline field policy.
 */

import {
  assertFieldPolicyDictionary,
  type FieldPolicyDescriptor,
} from '../../kernel/fieldPolicy'

export const DNS_HANDLER_FIELD_POLICY: readonly FieldPolicyDescriptor[] = [
  {
    variant: 'dns',
    fieldPath: 'header.flags',
    valueType: 'u16',
    identityRole: 'none',
    diagnosticAction: 'preserve',
    highPrivacyAction: 'preserve',
    preserveReason: 'DNS opcode/rcode flags',
    canaryKind: 'none',
  },
  {
    variant: 'dns',
    fieldPath: 'question.qname',
    valueType: 'domain',
    identityRole: 'name',
    diagnosticAction: 'map',
    highPrivacyAction: 'map',
    canaryKind: 'ascii',
  },
  {
    variant: 'dns',
    fieldPath: 'answer.rdata-a',
    valueType: 'ipv4',
    identityRole: 'address',
    diagnosticAction: 'map',
    highPrivacyAction: 'map',
    canaryKind: 'binary',
  },
  {
    variant: 'dns',
    fieldPath: 'answer.rdata-aaaa',
    valueType: 'ipv6',
    identityRole: 'address',
    diagnosticAction: 'map',
    highPrivacyAction: 'map',
    canaryKind: 'binary',
  },
  {
    variant: 'dns',
    fieldPath: 'answer.rdata-cname',
    valueType: 'domain',
    identityRole: 'name',
    diagnosticAction: 'map',
    highPrivacyAction: 'map',
    canaryKind: 'ascii',
  },
]

assertFieldPolicyDictionary(DNS_HANDLER_FIELD_POLICY)
