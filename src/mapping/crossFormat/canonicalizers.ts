/**
 * Versioned cross-format canonicalizers (Stage 25).
 */

import {
  normalizeIpv4Canonical,
  normalizeIpv6Canonical,
  normalizeMacCanonical,
} from '../sharedNormalize'
import type { CrossFormatCategory, CrossFormatSourceKind } from './types'

const MAX_LEN = 512

export function canonicalizeCrossFormatIpv4(raw: string, _source: CrossFormatSourceKind): string | null {
  void _source
  return normalizeIpv4Canonical(raw)
}

export function canonicalizeCrossFormatIpv6(raw: string, _source: CrossFormatSourceKind): string | null {
  void _source
  return normalizeIpv6Canonical(raw)
}

export function canonicalizeCrossFormatMac(raw: string, _source: CrossFormatSourceKind): string | null {
  void _source
  return normalizeMacCanonical(raw)
}

export function canonicalizeCrossFormatHostname(raw: string, _source: CrossFormatSourceKind): string | null {
  void _source
  const trimmed = raw.trim().toLowerCase().replace(/\.$/, '')
  if (trimmed.length === 0 || trimmed.length > MAX_LEN) return null
  if (!/^[a-z0-9.-]+$/.test(trimmed)) return null
  return trimmed
}

/** Port canonical form requires verified transport context: tcp|udp|sctp/port */
export function canonicalizeCrossFormatPort(raw: string, source: CrossFormatSourceKind): string | null {
  const trimmed = raw.trim().toLowerCase()
  if (source === 'pcap') {
    const slash = trimmed.indexOf('/')
    if (slash <= 0) return null
    const proto = trimmed.slice(0, slash)
    const port = Number(trimmed.slice(slash + 1))
    if (!Number.isInteger(port) || port < 0 || port > 65535) return null
    if (proto !== 'tcp' && proto !== 'udp' && proto !== 'sctp') return null
    return `${proto}/${port}`
  }
  // Text `:5060` or bare port without transport is not cross-format linkable.
  if (/^:\d{1,5}$/.test(trimmed) || /^\d{1,5}$/.test(trimmed)) return null
  const m = trimmed.match(/^(tcp|udp|sctp)\/(\d{1,5})$/i)
  if (!m) return null
  const port = Number(m[2])
  if (port > 65535) return null
  return `${m[1]!.toLowerCase()}/${port}`
}

/**
 * T45 — E.164 digits for proven international forms (`+…`, `tel:+…`).
 * `00…` is NOT auto-normalized without dialing context (separate identity).
 * National digits without `+` stay as national key (no country guessing).
 */
export function canonicalizeCrossFormatPhone(raw: string, _source: CrossFormatSourceKind): string | null {
  void _source
  let s = raw.trim()
  if (s.length === 0 || s.length > MAX_LEN) return null
  // Strip tel: / sip: wrappers and visual separators; keep leading + as international marker.
  s = s.replace(/^(?:tel|sip):/i, '')
  const hadPlus = s.startsWith('+')
  const digits = s.replace(/\D/g, '')
  if (digits.length < 3 || digits.length > 15) return null
  // Purely numeric short extensions without + are allowed as national keys.
  if (hadPlus) return `+${digits}`
  return digits
}

/** T45 — local-part case-sensitive; domain casefold. Not for AAA user@realm. */
export function canonicalizeCrossFormatEmail(raw: string, _source: CrossFormatSourceKind): string | null {
  void _source
  const trimmed = raw.trim()
  if (trimmed.length === 0 || trimmed.length > MAX_LEN) return null
  const at = trimmed.lastIndexOf('@')
  if (at <= 0 || at === trimmed.length - 1) return null
  const local = trimmed.slice(0, at)
  const domain = trimmed.slice(at + 1).toLowerCase()
  if (local.length === 0 || domain.length === 0 || domain.includes(' ')) return null
  if (!domain.includes('.')) return null
  return `${local}@${domain}`
}

/**
 * T45 — user principal includes realm/domain type.
 * DOMAIN\user and user@realm are distinct from bare local unless explicitly related later.
 */
export function canonicalizeCrossFormatUser(raw: string, _source: CrossFormatSourceKind): string | null {
  void _source
  const trimmed = raw.trim()
  if (trimmed.length === 0 || trimmed.length > MAX_LEN) return null
  const backslash = trimmed.indexOf('\\')
  if (backslash > 0) {
    const domain = trimmed.slice(0, backslash).toLowerCase()
    const user = trimmed.slice(backslash + 1)
    if (!domain || !user) return null
    return `nt:${domain}:${user.toLowerCase()}`
  }
  const at = trimmed.lastIndexOf('@')
  if (at > 0) {
    const user = trimmed.slice(0, at)
    const realm = trimmed.slice(at + 1).toLowerCase()
    if (!user || !realm) return null
    // Mailbox-shaped (has dot in realm) is email, not user principal.
    if (realm.includes('.')) return null
    return `realm:${realm}:${user.toLowerCase()}`
  }
  return `local:${trimmed.toLowerCase()}`
}

export function canonicalizeCrossFormatCategory(
  category: CrossFormatCategory,
  raw: string,
  source: CrossFormatSourceKind,
): string | null {
  switch (category) {
    case 'ipv4':
      return canonicalizeCrossFormatIpv4(raw, source)
    case 'ipv6':
      return canonicalizeCrossFormatIpv6(raw, source)
    case 'mac':
      return canonicalizeCrossFormatMac(raw, source)
    case 'hostname':
      return canonicalizeCrossFormatHostname(raw, source)
    case 'port':
      return canonicalizeCrossFormatPort(raw, source)
    case 'phone':
      return canonicalizeCrossFormatPhone(raw, source)
    case 'email':
      return canonicalizeCrossFormatEmail(raw, source)
    case 'user':
      return canonicalizeCrossFormatUser(raw, source)
  }
}
