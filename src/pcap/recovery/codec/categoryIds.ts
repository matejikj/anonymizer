/**
 * Stable numeric IDs for recovery lookup categories / match kinds.
 */

import type { RecoveryLookupCategory, RecoveryMatchKind } from '../domain/types'
import { RECOVERY_LOOKUP_CATEGORIES } from '../domain/types'

export const RECOVERY_CATEGORY_IDS: Readonly<Record<RecoveryLookupCategory, number>> = {
  ipv4: 1,
  ipv6: 2,
  mac: 3,
  vlan: 4,
  port: 5,
  hostname: 6,
  email: 7,
  url: 8,
  'sip-user': 9,
  'sip-phone': 10,
  'sip-call-id': 11,
  'sip-token': 12,
  'rtp-ssrc': 13,
  'radio-id': 14,
  other: 15,
  // T01 — append-only; never renumber existing IDs.
  'sdp-session-id': 16,
  // T14 — append-only.
  'opaque-id': 17,
  // T45 — append-only; email (7) / sip-phone (10) / sip-user (9) stay for legacy bundles.
  phone: 18,
  user: 19,
  // T16 — append-only.
  imsi: 20,
  imei: 21,
  // T20 — append-only.
  'snmp-engine-id': 22,
  // T26 — append-only.
  teid: 23,
  // T25 — append-only.
  'point-code': 24,
  // T40 — append-only.
  ssid: 25,
}

const ID_TO_CATEGORY: ReadonlyMap<number, RecoveryLookupCategory> = new Map(
  RECOVERY_LOOKUP_CATEGORIES.map((c) => [RECOVERY_CATEGORY_IDS[c], c]),
)

export const RECOVERY_MATCH_KIND_IDS: Readonly<Record<RecoveryMatchKind, number>> = {
  exact: 0,
  ambiguous: 1,
  redacted: 2,
}

export function categoryId(category: RecoveryLookupCategory): number {
  return RECOVERY_CATEGORY_IDS[category]
}

export function categoryFromId(id: number): RecoveryLookupCategory | null {
  return ID_TO_CATEGORY.get(id) ?? null
}

export function matchKindId(kind: RecoveryMatchKind): number {
  return RECOVERY_MATCH_KIND_IDS[kind]
}

export function matchKindFromId(id: number): RecoveryMatchKind | null {
  if (id === 0) return 'exact'
  if (id === 1) return 'ambiguous'
  if (id === 2) return 'redacted'
  return null
}

/** Map mapping/entity categories onto recovery lookup categories. */
export function toRecoveryLookupCategory(raw: string): RecoveryLookupCategory {
  switch (raw) {
    case 'ipv4':
    case 'ipv6':
    case 'mac':
    case 'vlan':
    case 'port':
    case 'hostname':
    case 'email':
    case 'url':
    case 'sip-user':
    case 'sip-phone':
    case 'sip-call-id':
    case 'sip-token':
    case 'sdp-session-id':
    case 'opaque-id':
    case 'phone':
    case 'user':
    case 'imsi':
    case 'imei':
    case 'snmp-engine-id':
    case 'teid':
    case 'point-code':
    case 'ssid':
      return raw
    case 'free-token':
      // T69 — recover under opaque-id bucket (length-stable text token).
      return 'opaque-id'
    case 'user-id':
      // T45 — text user-id seeds the cross-format user recovery ID.
      return 'user'
    case 'ssrc':
    case 'rtp-ssrc':
      return 'rtp-ssrc'
    case 'radioId':
    case 'radio-id':
      return 'radio-id'
    case 'ip':
      return 'ipv4'
    default:
      return 'other'
  }
}
