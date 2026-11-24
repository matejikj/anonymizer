/**
 * Shared binary-oriented normalizers for IP/MAC used by text and PCAP paths.
 */

import { expandIpv6Canonical } from './ipv6Semantics.ts'

export function normalizeIpv4Canonical(raw: string): string | null {
  const parts = raw.trim().split('.')
  if (parts.length !== 4) return null
  const nums: number[] = []
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null
    const n = Number(p)
    if (n > 255) return null
    nums.push(n)
  }
  return nums.join('.')
}

/** Expanded 8-hextet lowercase form (T33) so solicited-node / embedded-IPv4 match across spellings. */
export function normalizeIpv6Canonical(raw: string): string | null {
  return expandIpv6Canonical(raw)
}

export function normalizeMacCanonical(raw: string): string | null {
  const hex = raw.trim().toLowerCase().replace(/[-.]/g, ':')
  const parts = hex.split(':')
  if (parts.length !== 6) return null
  for (const p of parts) {
    if (!/^[0-9a-f]{2}$/.test(p)) return null
  }
  return parts.join(':')
}
