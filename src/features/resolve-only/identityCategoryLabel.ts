/**
 * Czech labels for all identity categories (text + PCAP) in resolve workspace.
 */

import type { IdentityCategory } from '../../mapping/identityCategories'
import { CATEGORY_LABELS } from '../review/categoryLabels.ts'

const PCAP_LABELS: Partial<Record<IdentityCategory, string>> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  mac: 'MAC',
  hostname: 'Hostname (PCAP)',
  vlan: 'VLAN',
  port: 'Port',
  timestamp: 'Timestamp',
  radioId: 'Radio ID',
  ssrc: 'RTP SSRC',
  'sdp-session-id': 'SDP session-id',
  'opaque-id': 'Neprůhledné ID',
  imsi: 'IMSI',
  imei: 'IMEI',
  'snmp-engine-id': 'SNMP engine ID',
  teid: 'GTP TEID',
  'point-code': 'SS7 point code',
  ssid: 'SSID (802.11 / RADIUS)',
  'sip-call-id': 'SIP Call-ID',
  'sip-token': 'SIP token',
  'sip-user': 'SIP uživatel',
}

export function identityCategoryLabel(category: IdentityCategory): string {
  if (category in CATEGORY_LABELS) {
    return CATEGORY_LABELS[category as keyof typeof CATEGORY_LABELS]
  }
  return PCAP_LABELS[category] ?? category
}
