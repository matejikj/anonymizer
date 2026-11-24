/**
 * Unified identity categories for text and PCAP (Stage 18).
 */

import type { Category } from '../domain/types'
import type { EntityCategory } from '../pcap/anonymization/entityRegistry'

export type TextIdentityCategory = Category
export type PcapIdentityCategory = EntityCategory
export type IdentityCategory = TextIdentityCategory | PcapIdentityCategory

const PCAP_CATEGORIES = new Set<PcapIdentityCategory>([
  'ipv4', 'ipv6', 'mac', 'hostname', 'vlan', 'port', 'timestamp', 'radioId', 'ssrc',
  'sdp-session-id',
  'opaque-id',
  'sip-call-id', 'sip-token', 'sip-user',
  'imsi', 'imei',
  'snmp-engine-id',
  'teid',
  'point-code',
  'ssid',
  'free-token',
])

const TEXT_CATEGORIES = new Set<TextIdentityCategory>([
  'ip', 'hostname', 'sip-phone', 'email', 'person', 'user-id', 'internal-id', 'port', 'custom',
])

export function isPcapIdentityCategory(c: IdentityCategory): c is PcapIdentityCategory {
  return PCAP_CATEGORIES.has(c as PcapIdentityCategory)
}

export function isTextIdentityCategory(c: IdentityCategory): c is TextIdentityCategory {
  return TEXT_CATEGORIES.has(c as TextIdentityCategory)
}

export const ALL_IDENTITY_CATEGORIES: readonly IdentityCategory[] = [
  ...TEXT_CATEGORIES,
  ...PCAP_CATEGORIES,
] as IdentityCategory[]
