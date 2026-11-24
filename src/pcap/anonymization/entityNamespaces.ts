/**
 * Enterprise step 12 — entity crypto namespaces.
 *
 * Each namespace has its own allocation pool / map key prefix. Never mix SSRC
 * into the IP pool (or VLAN into PORT, …). Cross-entity relationships stay as
 * graph edges in the capture, not shared alias spaces.
 */

import type { EntityCategory } from './entityRegistry'
import type { IdentityCategory } from '../../mapping/identityCategories'

/** Formal identity namespaces (review / step 12). */
export const ENTITY_NAMESPACES = [
  'IP',
  'MAC',
  'VLAN',
  'PORT',
  'PHONE',
  'HOSTNAME',
  'SIP_CALL_ID',
  'SIP_TAG',
  'SIP_BRANCH',
  'SSRC',
  'SDP_SESSION_ID',
  'OPAQUE_ID',
  'IMSI',
  'IMEI',
  'SNMP_ENGINE_ID',
  'TEID',
  'POINT_CODE',
  'SSID',
  'USERNAME',
  'RADIO_ID',
  'TIMESTAMP',
] as const

export type EntityNamespace = (typeof ENTITY_NAMESPACES)[number]

/**
 * Map a concrete category onto its crypto namespace.
 * Categories that share a namespace (ipv4/ipv6 → IP) still use distinct map keys
 * (`ipv4:…` vs `ipv6:…`) so families never collide — but they must not share
 * allocation sets with unrelated namespaces (e.g. SSRC).
 */
export function entityNamespaceFor(
  category: IdentityCategory | EntityCategory | string,
): EntityNamespace {
  switch (category) {
    case 'ipv4':
    case 'ipv6':
    case 'ip':
      return 'IP'
    case 'mac':
      return 'MAC'
    case 'vlan':
      return 'VLAN'
    case 'port':
      return 'PORT'
    case 'sip-phone':
    case 'phone':
      return 'PHONE'
    case 'hostname':
      return 'HOSTNAME'
    case 'sip-call-id':
      return 'SIP_CALL_ID'
    case 'sip-token':
      // tag / branch / generic SIP tokens share the SIP_TAG namespace family;
      // call-id stays separate so dialog identity is not mixed with via-branch.
      return 'SIP_TAG'
    case 'sip-user':
    case 'user-id':
    case 'person':
      return 'USERNAME'
    case 'ssrc':
      return 'SSRC'
    case 'sdp-session-id':
      return 'SDP_SESSION_ID'
    case 'imsi':
      return 'IMSI'
    case 'imei':
      return 'IMEI'
    case 'snmp-engine-id':
      return 'SNMP_ENGINE_ID'
    case 'teid':
      return 'TEID'
    case 'point-code':
      return 'POINT_CODE'
    case 'ssid':
      return 'SSID'
    case 'opaque-id':
    case 'free-token':
      return 'OPAQUE_ID'
    case 'radioId':
      return 'RADIO_ID'
    case 'timestamp':
      return 'TIMESTAMP'
    default:
      // Unknown categories get an isolated USERNAME-like bucket rather than IP.
      return 'USERNAME'
  }
}

/** Registry / SessionMapping key — namespace isolation starts with category prefix. */
export function entityMapKey(
  category: IdentityCategory | EntityCategory | string,
  canonical: string,
): string {
  return `${category}:${canonical}`
}

/**
 * True when two categories must never share an exclusive-allocation set.
 * (Same namespace may still use separate used-sets per family, e.g. ipv4 vs ipv6.)
 */
export function namespacesMustStayIsolated(
  a: IdentityCategory | EntityCategory | string,
  b: IdentityCategory | EntityCategory | string,
): boolean {
  return entityNamespaceFor(a) !== entityNamespaceFor(b)
}

/** Step 12 — IP mode is bound to the PCAP profile (not a third UI toggle). */
export type IpMappingMode = 'topology-preserving' | 'privacy-preserving'

export function ipModeForProfile(
  profile: 'diagnostic' | 'high-privacy',
): IpMappingMode {
  return profile === 'high-privacy' ? 'privacy-preserving' : 'topology-preserving'
}

export function isIpMappingMode(value: unknown): value is IpMappingMode {
  return value === 'topology-preserving' || value === 'privacy-preserving'
}
