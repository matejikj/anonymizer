/**
 * Text canonical identity normalization (Stage 18).
 * Category-specific rules — not a blanket toLowerCase().
 */

import type { Category } from '../domain/types'
import { normalizeIpv4Canonical, normalizeIpv6Canonical } from './sharedNormalize'

export const MAX_TEXT_CANONICAL_LENGTH = 512

export function canonicalizeTextIdentity(category: Category, raw: string): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_TEXT_CANONICAL_LENGTH) {
    return null
  }

  switch (category) {
    case 'ip':
      return normalizeTextIp(raw)
    case 'hostname':
      return normalizeTextHostname(raw)
    case 'email':
      return normalizeTextEmail(raw)
    case 'person':
      return normalizeTextPerson(raw)
    case 'user-id':
      return normalizeTextUserId(raw)
    case 'internal-id':
      return normalizeTextInternalId(raw)
    case 'sip-phone':
      return normalizeTextSipPhone(raw)
    case 'port':
      return normalizeTextPort(raw)
    case 'custom':
      return raw
  }
}

function normalizeTextIp(raw: string): string | null {
  const trimmed = raw.trim()
  if (trimmed.includes(':')) {
    return normalizeIpv6Canonical(trimmed)
  }
  return normalizeIpv4Canonical(trimmed)
}

function normalizeTextHostname(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase().replace(/\.$/, '')
  if (trimmed.length === 0) return null
  return trimmed
}

function normalizeTextEmail(raw: string): string | null {
  const at = raw.lastIndexOf('@')
  if (at < 0) return null
  const local = raw.slice(0, at).trim()
  const domain = raw.slice(at + 1).trim().toLowerCase()
  if (local.length === 0 || domain.length === 0) return null
  return `${local}@${domain}`
}

function normalizeTextPerson(raw: string): string | null {
  const normalized = raw.trim().replace(/\s+/g, ' ').toLowerCase()
  return normalized.length > 0 ? normalized : null
}

function normalizeTextUserId(raw: string): string | null {
  const normalized = raw.trim().toLowerCase()
  return normalized.length > 0 ? normalized : null
}

function normalizeTextInternalId(raw: string): string | null {
  const normalized = raw.trim()
  return normalized.length > 0 ? normalized : null
}

/**
 * T45 — preserve international `+` marker so cross-format phone keys match
 * `tel:+…` / `sip:+…` without merging national digit strings of the same length.
 */
function normalizeTextSipPhone(raw: string): string | null {
  const trimmed = raw.trim()
  const afterScheme = trimmed.replace(/^(?:tel|sip):/i, '')
  const hadPlus = afterScheme.startsWith('+') || trimmed.includes('+')
  const digits = trimmed.replace(/\D/g, '')
  if (digits.length === 0) return null
  return hadPlus ? `+${digits}` : digits
}

function normalizeTextPort(raw: string): string | null {
  const digits = raw.replace(/\D/g, '')
  if (digits.length === 0) return null
  const n = Number.parseInt(digits, 10)
  if (!Number.isInteger(n) || n < 1 || n > 65535) return null
  return String(n)
}

export function defaultTextWireConstraint(
  category: Category,
  canonical: string,
  originalSpelling?: string,
): import('./types').WireRepresentationConstraint {
  const sample = originalSpelling ?? canonical
  switch (category) {
    case 'ip':
      return canonical.includes(':') ? { kind: 'ipv6-wire' } : { kind: 'ipv4-wire' }
    case 'hostname':
      return { kind: 'text-ascii', byteLength: new TextEncoder().encode(sample).length }
    case 'sip-phone':
    case 'email':
    case 'person':
    case 'user-id':
    case 'internal-id':
    case 'port':
    case 'custom':
      return { kind: 'text-ascii', byteLength: new TextEncoder().encode(sample).length }
  }
}
