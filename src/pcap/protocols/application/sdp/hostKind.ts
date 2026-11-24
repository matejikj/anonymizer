/**
 * Host classification helpers for SDP addresses.
 */

import type { SdpMappingCategory } from './types';

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export function sdpAddressCategory(addressText: string, addrTypeText: string): SdpMappingCategory {
  const addrType = addrTypeText.toUpperCase();
  if (addrType === 'IP4') return 'ipv4';
  if (addrType === 'IP6') return 'ipv6';
  if (IPV4_RE.test(addressText)) return 'ipv4';
  if (addressText.includes(':')) return 'ipv6';
  return 'hostname';
}

export function sdpEntityKindForAddress(category: SdpMappingCategory): 'ipv4' | 'ipv6' | 'host' {
  if (category === 'ipv4') return 'ipv4';
  if (category === 'ipv6') return 'ipv6';
  return 'host';
}

/** Strip optional `/ttl` or `/multicast` suffix from SDP connection address. */
export function normalizeSdpAddress(addressText: string): string {
  const slash = addressText.indexOf('/');
  return slash >= 0 ? addressText.slice(0, slash) : addressText;
}
