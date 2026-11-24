/**
 * T14 — HTTP/1.x field policy dictionary (compiled with T-01 facts; not a second registry).
 */

import {
  assertFieldPolicyDictionary,
  type FieldPolicyDescriptor,
} from './fieldPolicy'

export const HTTP_FIELD_DICTIONARY: readonly FieldPolicyDescriptor[] = [
  {
    variant: 'http/1.x',
    fieldPath: 'header.host',
    valueType: 'authority',
    identityRole: 'address',
    identityScope: 'session',
    wireEncoder: 'fixed-ascii',
    diagnosticAction: 'map',
    highPrivacyAction: 'map',
  },
  {
    variant: 'http/1.x',
    fieldPath: 'header.cookie',
    valueType: 'opaque',
    identityRole: 'secret',
    diagnosticAction: 'mask',
    highPrivacyAction: 'mask',
  },
  {
    variant: 'http/1.x',
    fieldPath: 'header.authorization',
    valueType: 'opaque',
    identityRole: 'secret',
    diagnosticAction: 'mask',
    highPrivacyAction: 'mask',
  },
  {
    variant: 'http/1.x',
    fieldPath: 'header.set-cookie',
    valueType: 'opaque',
    identityRole: 'secret',
    diagnosticAction: 'mask',
    highPrivacyAction: 'mask',
  },
  {
    variant: 'http/1.x',
    fieldPath: 'header.date',
    valueType: 'http-date',
    identityRole: 'none',
    diagnosticAction: 'time',
    highPrivacyAction: 'time',
    preserveReason: 'capture-aligned absolute time (PayloadTimeSession)',
  },
  {
    variant: 'http/1.x',
    fieldPath: 'header.last-modified',
    valueType: 'http-date',
    identityRole: 'none',
    diagnosticAction: 'time',
    highPrivacyAction: 'time',
    preserveReason: 'capture-aligned absolute time (PayloadTimeSession)',
  },
  {
    variant: 'http/1.x',
    fieldPath: 'body',
    valueType: 'opaque',
    identityRole: 'content',
    diagnosticAction: 'mask',
    highPrivacyAction: 'mask',
  },
]

assertFieldPolicyDictionary(HTTP_FIELD_DICTIONARY)
