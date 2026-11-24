/**
 * Typed sensitive entities extracted from a parsed SIP message (step 4).
 * Each entity carries an absolute byte span into the original payload buffer.
 */

import type { ByteSpan } from './types';

/** Semantic kind of a sensitive SIP field. */
export type SipEntityKind =
  | 'display-name'
  | 'sip-user'
  | 'tel-phone'
  | 'sip-password'
  | 'host'
  | 'ipv4'
  | 'ipv6'
  | 'port'
  | 'uri-parameter'
  | 'header-parameter'
  | 'call-id'
  | 'sip-token'
  | 'credential-value'
  | 'opaque-text';

/** How the entity should be transformed during anonymization. */
export type SipEntityAction = 'map' | 'redact' | 'allow';

/**
 * Mapping category for `map` actions.
 * SIP-specific categories are wired into discovery and MappingAuthority (step 6).
 */
export type SipMappingCategory =
  | 'ipv4'
  | 'ipv6'
  | 'hostname'
  | 'port'
  | 'sip-call-id'
  | 'sip-token'
  | 'sip-phone'
  | 'sip-user';

export interface SipSensitiveEntity {
  readonly kind: SipEntityKind;
  readonly span: ByteSpan;
  readonly action: SipEntityAction;
  /** Decoded text for canonicalization / mapping lookup. Empty for redact-only spans. */
  readonly canonicalText: string;
  /** Canonical header name (`from`, `via`, …) or `request-uri` for the start-line URI. */
  readonly headerCanonicalName: string;
  /** Parameter name when the entity is a header/URI parameter value. */
  readonly parameterName: string | null;
  /** Present only when `action === 'map'`. */
  readonly mappingCategory: SipMappingCategory | null;
}

export interface SipExtractionResult {
  readonly entities: readonly SipSensitiveEntity[];
  readonly issues: readonly string[];
}

export interface SipRedactionOperation {
  readonly span: ByteSpan;
  readonly action: 'map' | 'redact';
  readonly mappingCategory: SipMappingCategory | null;
  readonly canonicalText: string;
  readonly maskByte: number;
}

export interface SipRedactionPlan {
  readonly operations: readonly SipRedactionOperation[];
}
