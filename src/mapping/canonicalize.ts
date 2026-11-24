/**
 * Unified canonical identity entry point for text and PCAP (Stage 18).
 */

import { assertNever } from '../domain/assertNever'
import type { Category } from '../domain/types'
import type { EntityCategory } from '../pcap/anonymization/entityRegistry'
import type { IdentityCategory } from './identityCategories'
import { isPcapIdentityCategory, isTextIdentityCategory } from './identityCategories'
import { canonicalizePcapIdentity } from './pcapCanonical'
import { canonicalizeTextIdentity } from './textCanonical'
import type { WireRepresentationConstraint } from './types'
import { defaultWireConstraint } from './pcapCanonical'
import { defaultTextWireConstraint } from './textCanonical'

/** PCAP wire ports use proto/port; text log ports are bare numbers or :port suffixes. */
function isWireTransportPort(raw: string): boolean {
  const trimmed = raw.trim().toLowerCase()
  const slash = trimmed.indexOf('/')
  if (slash <= 0) return false
  const proto = trimmed.slice(0, slash)
  return proto === 'tcp' || proto === 'udp' || proto === 'sctp'
}

export function canonicalizeIdentity(category: IdentityCategory, raw: string): string | null {
  if (category === 'port') {
    return isWireTransportPort(raw)
      ? canonicalizePcapIdentity('port', raw)
      : canonicalizeTextIdentity('port', raw)
  }
  if (isTextIdentityCategory(category)) {
    return canonicalizeTextIdentity(category, raw)
  }
  if (isPcapIdentityCategory(category)) {
    return canonicalizePcapIdentity(category, raw)
  }
  return assertNever(category as never, 'canonicalizeIdentity')
}

export function defaultIdentityWireConstraint(
  category: IdentityCategory,
  canonical: string,
  originalSpelling?: string,
): WireRepresentationConstraint | null {
  if (category === 'port') {
    return isWireTransportPort(canonical)
      ? defaultWireConstraint('port', canonical)
      : defaultTextWireConstraint('port', canonical, originalSpelling)
  }
  if (isTextIdentityCategory(category)) {
    return defaultTextWireConstraint(category, canonical, originalSpelling)
  }
  if (isPcapIdentityCategory(category)) {
    if (
      category === 'sip-call-id'
      || category === 'sip-token'
      || category === 'sip-user'
      || category === 'sdp-session-id'
      || category === 'imsi'
      || category === 'imei'
      || category === 'snmp-engine-id'
      || category === 'opaque-id'
    ) {
      const sample = originalSpelling ?? canonical
      // SDP session-id / SIP tokens are Latin-1 wire spans — byteLength === string length.
      return { kind: 'text-ascii', byteLength: sample.length }
    }
    return defaultWireConstraint(category as EntityCategory, canonical)
  }
  return assertNever(category as never, 'defaultIdentityWireConstraint')
}

/** Category separation guard — same spelling in different categories must not share a key. */
export function identityMappingKey(category: IdentityCategory, canonical: string): string {
  return `${category}:${canonical}`
}

export function categoriesShareCanonical(
  a: IdentityCategory,
  b: IdentityCategory,
  _raw: string,
): boolean {
  if (a !== b) return false
  return true
}

export { canonicalizeTextIdentity, canonicalizePcapIdentity }

export type { Category, EntityCategory }
