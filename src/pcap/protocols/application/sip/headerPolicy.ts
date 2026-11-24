/**
 * Explicit allowlist / redact rules for SIP headers (enterprise step 8).
 */

export type SipHeaderDisposition =
  /** Parse name-addrs / URIs (From, To, Contact, …). */
  | 'identity'
  /** STIR/SHAKEN Identity / PASSporT — full-token mask; crypto MODIFIED. */
  | 'stir-identity'
  /** Map Call-ID token. */
  | 'call-id'
  /** Via sent-by host/port + branch parameter. */
  | 'via'
  /** Digest / auth challenges — fixed mask, never mapped. */
  | 'credential'
  /** Opaque product strings (User-Agent, Server, …). */
  | 'opaque-redact'
  /** Unknown vendor P-* / X-* headers. */
  | 'vendor-redact'
  /** Structural — no extraction (Content-Length, CSeq, …). */
  | 'structural'
  /** T14 — absolute HTTP-date style wall clock; capture-aligned shift or mask. */
  | 'absolute-time'
  /** T53 — Geolocation / Geolocation-Routing: cid map; location URI mask. */
  | 'geolocation'

const IDENTITY_HEADERS = new Set([
  'from',
  'to',
  'contact',
  'route',
  'record-route',
  'reply-to',
  'refer-to',
  'referred-by',
  'p-asserted-identity',
  'p-preferred-identity',
  'p-associated-uri',
  'p-called-party-id',
  'remote-party-id',
  'diversion',
  'history-info',
  'path',
  'service-route',
]);

/** RFC 8224 STIR/SHAKEN — JWT PASSporT; never map, always mask. */
const STIR_IDENTITY_HEADERS = new Set([
  'identity',
]);

const CREDENTIAL_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'authentication-info',
  'proxy-authentication-info',
  'www-authenticate',
  'proxy-authenticate',
]);

// NB: User-Agent is deliberately NOT preserved here. A first pass at this audit finding
// considered moving it to a preserve disposition (generic vendor/version banners are low-risk
// diagnostic value elsewhere), but the local private regression capture disproves that assumption for this
// traffic: its User-Agent values are deployment-identifying device/product strings (radio
// terminal model + firmware build, internal gateway build/revision timestamps) — exactly what
// "removes identities" (this tool's own diagnostic-profile promise) must redact. `Server`
// values in the same capture are the opposite (a generic "Asterisk PBX 22.0.0" banner), which
// is why it — unlike User-Agent — would be a reasonable candidate to preserve in the future.
const OPAQUE_REDACT_HEADERS = new Set([
  'user-agent',
  'server',
  'organization',
  'subject',
  'call-info',
  'alert-info',
  'error-info',
  'warning',
  'identity-info',
  'geolocation-error',
]);

const GEOLOCATION_HEADERS = new Set([
  'geolocation',
  'geolocation-routing',
]);

const STRUCTURAL_HEADERS = new Set([
  'content-length',
  'content-type',
  'cseq',
  'max-forwards',
  'expires',
  'min-expires',
  'session-expires',
  'min-se',
  'allow',
  'supported',
  'require',
  'privacy',
  'event',
  'subscription-state',
  'accept',
  'accept-encoding',
  'accept-language',
  // T53 — RFC 4412 Resource-Priority namespaces/values are schema enums (preserve)
  'resource-priority',
  'accept-resource-priority',
  'priority',
]);

/** Well-known correlation URI / header parameters that map stably. */
export const CORRELATION_PARAMETERS = new Set([
  'tag',
  'branch',
  'gr',
  'gruu',
  'uuid',
  'id',
  'cid',
]);

export function dispositionForHeader(canonicalName: string): SipHeaderDisposition {
  if (STIR_IDENTITY_HEADERS.has(canonicalName)) return 'stir-identity';
  if (IDENTITY_HEADERS.has(canonicalName)) return 'identity';
  if (CREDENTIAL_HEADERS.has(canonicalName)) return 'credential';
  if (canonicalName === 'call-id') return 'call-id';
  if (canonicalName === 'via') return 'via';
  if (canonicalName === 'date') return 'absolute-time';
  if (GEOLOCATION_HEADERS.has(canonicalName)) return 'geolocation';
  if (OPAQUE_REDACT_HEADERS.has(canonicalName)) return 'opaque-redact';
  if (STRUCTURAL_HEADERS.has(canonicalName)) return 'structural';
  if (canonicalName.startsWith('p-') || canonicalName.startsWith('x-')) return 'vendor-redact';
  return 'vendor-redact';
}
