/**
 * Classify host strings as IPv4, IPv6, or hostname.
 */

import type { SipMappingCategory } from './entities';

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export function hostMappingCategory(hostText: string): SipMappingCategory {
  if (IPV4_RE.test(hostText)) return 'ipv4';
  if (hostText.includes(':')) return 'ipv6';
  return 'hostname';
}

export function entityKindForHost(category: SipMappingCategory): 'ipv4' | 'ipv6' | 'host' {
  if (category === 'ipv4') return 'ipv4';
  if (category === 'ipv6') return 'ipv6';
  return 'host';
}
