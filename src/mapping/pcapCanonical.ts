/**
 * PCAP canonical identity normalization (Stage 7).
 * Stage 18 extends this with text categories; Stage 7 covers PCAP only.
 */

import type { EntityCategory } from '../pcap/anonymization/entityRegistry'
import { normalizeImsiDigits } from '../pcap/protocols/application/binproto/tbcd'
import {
  normalizeIpv4Canonical,
  normalizeIpv6Canonical,
  normalizeMacCanonical,
} from './sharedNormalize'
import type { WireRepresentationConstraint } from './types'

const MAX_CANONICAL_STRING_LENGTH = 512

export function maxCanonicalStringLength(): number {
  return MAX_CANONICAL_STRING_LENGTH
}

export function canonicalizePcapIdentity(category: EntityCategory, raw: string): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_CANONICAL_STRING_LENGTH) {
    return null
  }

  switch (category) {
    case 'ipv4':
      return normalizeIpv4(raw)
    case 'ipv6':
      return normalizeIpv6(raw)
    case 'mac':
      return normalizeMac(raw)
    case 'hostname':
      return normalizeHostname(raw)
    case 'vlan':
      return normalizeVlan(raw)
    case 'port':
      return normalizePort(raw)
    case 'radioId':
      return normalizeRadioId(raw)
    case 'ssrc':
      return normalizeSsrc(raw)
    case 'sdp-session-id':
      return normalizeSdpSessionId(raw)
    case 'imsi':
      return normalizeImsi(raw)
    case 'imei':
      return normalizeImei(raw)
    case 'snmp-engine-id':
      return normalizeSnmpEngineId(raw)
    case 'teid':
      return normalizeTeid(raw)
    case 'point-code':
      return normalizePointCode(raw)
    case 'ssid':
      return normalizeSsid(raw)
    case 'opaque-id':
      return normalizeOpaqueId(raw)
    case 'free-token':
      return normalizeFreeToken(raw)
    case 'opaque-bin-id':
      return normalizeOpaqueBinId(raw)
    case 'timestamp':
      return raw
    case 'sip-call-id':
      return normalizeSipCallId(raw)
    case 'sip-token':
      return normalizeSipToken(raw)
    case 'sip-user':
      return normalizeSipUser(raw)
    default:
      return null
  }
}

export function defaultWireConstraint(
  category: EntityCategory,
  canonical: string,
): WireRepresentationConstraint | null {
  switch (category) {
    case 'ipv4':
      return { kind: 'ipv4-wire' }
    case 'ipv6':
      return { kind: 'ipv6-wire' }
    case 'mac':
      return { kind: 'mac-wire' }
    case 'hostname': {
      const labels = canonical.split('.')
      const maxLabelLength = Math.max(1, ...labels.map((l) => l.length))
      return { kind: 'hostname-ascii', labelCount: labels.length, maxLabelLength }
    }
    case 'port': {
      const proto = canonical.includes('/') ? canonical.split('/')[0]! : 'unknown'
      const p = proto === 'tcp' || proto === 'udp' || proto === 'sctp' ? proto : 'unknown'
      return { kind: 'port-wire', protocol: p }
    }
    case 'vlan':
      return { kind: 'vlan-wire' }
    case 'radioId':
      return { kind: 'radio-id-wire', bitWidth: 24 }
    case 'ssrc':
      return { kind: 'ssrc-wire' }
    case 'teid':
      // Same 32-bit BE wire shape as SSRC; identity namespace stays separate.
      return { kind: 'ssrc-wire' }
    case 'point-code':
      // Stored as text-ascii canonical; concrete wire width from originalSpelling.
      return { kind: 'text-ascii', byteLength: canonical.length }
    case 'ssid':
      // Binary octets on wire; byte length from original span (not canonical hex string).
      return null
    case 'sdp-session-id':
      // Length-stable digit string — wire width is the digit part (author scope is map-key only).
      return { kind: 'text-ascii', byteLength: sdpSessionIdDigits(canonical).length }
    case 'imsi':
    case 'imei':
      return { kind: 'text-ascii', byteLength: canonical.length }
    case 'snmp-engine-id':
      return { kind: 'text-ascii', byteLength: canonical.length }
    case 'opaque-id':
      return { kind: 'text-ascii', byteLength: canonical.length }
    case 'free-token':
      return { kind: 'text-ascii', byteLength: canonical.length }
    case 'opaque-bin-id':
      // Wire width from original span; canonical is lowercase hex of octets.
      return null
    case 'timestamp':
      return { kind: 'timestamp-wire' }
    default:
      return null
  }
}

function normalizeIpv4(raw: string): string | null {
  return normalizeIpv4Canonical(raw)
}

function normalizeIpv6(raw: string): string | null {
  return normalizeIpv6Canonical(raw)
}

function normalizeMac(raw: string): string | null {
  return normalizeMacCanonical(raw)
}

function normalizeHostname(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase().replace(/\.$/, '')
  if (trimmed.length === 0 || trimmed.length > MAX_CANONICAL_STRING_LENGTH) return null
  if (!/^[a-z0-9.-]+$/.test(trimmed)) return null
  return trimmed
}

function normalizeVlan(raw: string): string | null {
  const n = Number(raw.trim())
  if (!Number.isInteger(n) || n < 0 || n > 4095) return null
  return String(n)
}

function normalizePort(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase()
  const slash = trimmed.indexOf('/')
  if (slash <= 0) return null
  const proto = trimmed.slice(0, slash)
  const port = Number(trimmed.slice(slash + 1))
  if (!Number.isInteger(port) || port < 0 || port > 65535) return null
  if (proto !== 'tcp' && proto !== 'udp' && proto !== 'sctp') return null
  return `${proto}/${port}`
}

function normalizeRadioId(raw: string): string | null {
  const n = Number(raw.trim())
  if (!Number.isInteger(n) || n < 0 || n > 0xffffff) return null
  return String(n)
}

function normalizeSsrc(raw: string): string | null {
  const trimmed = raw.trim()
  if (!/^\d+$/.test(trimmed)) return null
  const n = Number(trimmed)
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) return null
  return String(n >>> 0)
}

/** T26 — GTP TEID as decimal string of unsigned 32-bit value. */
function normalizeTeid(raw: string): string | null {
  return normalizeSsrc(raw)
}

/** T40 — raw SSID octets as `ssid/<lowercase-hex>` (1–32 bytes ⇒ 2–64 hex digits). */
function normalizeSsid(raw: string): string | null {
  const trimmed = raw.trim()
  if (!trimmed.startsWith('ssid/')) return null
  const hex = trimmed.slice('ssid/'.length).toLowerCase()
  if (hex.length === 0 || hex.length > 64 || hex.length % 2 !== 0) return null
  if (!/^[0-9a-f]+$/.test(hex)) return null
  return `ssid/${hex}`
}

/** T25 — `pc/14/<n>` or `pc/24/<n>` (decimal n in range for width). */
function normalizePointCode(raw: string): string | null {
  const m = /^pc\/(14|24)\/(\d{1,8})$/.exec(raw.trim())
  if (!m) return null
  const width = Number(m[1])
  const n = Number(m[2])
  if (!Number.isInteger(n) || n < 0) return null
  const max = width === 14 ? 0x3fff : 0xffffff
  if (n > max) return null
  return `pc/${width}/${n}`
}

/**
 * T01 — SDP o= session-id namespace separator (username scope \\x1f digits).
 * Wire still carries only the digit token; scope is map-key only.
 */
export const SDP_SESSION_ID_SCOPE_SEP = '\u001f'

/** Digit part of a (possibly author-scoped) sdp-session-id canonical. */
export function sdpSessionIdDigits(canonical: string): string {
  const sep = canonical.lastIndexOf(SDP_SESSION_ID_SCOPE_SEP)
  return sep >= 0 ? canonical.slice(sep + 1) : canonical
}

/** Build author-scoped session-id canonical (`username\\x1fdigits`). */
export function scopeSdpSessionId(username: string, sessionIdDigits: string): string {
  return `${username}${SDP_SESSION_ID_SCOPE_SEP}${sessionIdDigits}`
}

/**
 * SDP o= session-id — digit string 1–64, optionally scoped as `username\\x1fdigits`.
 * Never Number (preserves values above 2^53).
 */
function normalizeSdpSessionId(raw: string): string | null {
  const trimmed = raw.trim()
  const sep = trimmed.indexOf(SDP_SESSION_ID_SCOPE_SEP)
  if (sep >= 0) {
    const user = trimmed.slice(0, sep)
    const digits = trimmed.slice(sep + 1)
    // Username token: non-empty, no further separators / controls (SDP token-ish).
    if (!user || user.includes(SDP_SESSION_ID_SCOPE_SEP) || /[\x00-\x1e\x7f]/.test(user)) {
      return null
    }
    if (!/^\d{1,64}$/.test(digits)) return null
    return `${user}${SDP_SESSION_ID_SCOPE_SEP}${digits}`
  }
  if (!/^\d{1,64}$/.test(trimmed)) return null
  return trimmed
}

/** T16 — IMSI digit string 5–15, optional PLMN scope (`plmn\\x1fmsin`) when MNC known. */
function normalizeImsi(raw: string): string | null {
  return normalizeImsiDigits(raw.trim())
}

/** T16 — IMEI 14–15 / IMEISV 16 digits. */
function normalizeImei(raw: string): string | null {
  const digits = raw.trim().replace(/\D/g, '')
  if (digits.length < 14 || digits.length > 16) return null
  return digits
}

/** T20 — SNMPv3 engine ID as lowercase hex (5–32 octets ⇒ 10–64 hex chars). */
function normalizeSnmpEngineId(raw: string): string | null {
  const hex = raw.trim().toLowerCase().replace(/[^0-9a-f]/g, '')
  if (hex.length < 10 || hex.length > 64 || hex.length % 2 !== 0) return null
  return hex
}

/** T14 — opaque printable ASCII token (1–256), length-stable alias. */
function normalizeOpaqueId(raw: string): string | null {
  const trimmed = raw.trim()
  if (trimmed.length === 0 || trimmed.length > 256) return null
  if (!/^[\x20-\x7E]+$/.test(trimmed)) return null
  return trimmed
}

/** T69 — free-text token canonical (case-folded, length 1–256). */
function normalizeFreeToken(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase()
  if (trimmed.length === 0 || trimmed.length > 256) return null
  return trimmed
}

/** T74 — binary opaque id as lowercase hex (1–64 octets ⇒ 2–128 hex chars). */
function normalizeOpaqueBinId(raw: string): string | null {
  const hex = raw.trim().toLowerCase().replace(/[^0-9a-f]/g, '')
  if (hex.length < 2 || hex.length > 128 || hex.length % 2 !== 0) return null
  return hex
}

function normalizeSipCallId(raw: string): string | null {
  const trimmed = raw.trim()
  if (trimmed.length === 0 || trimmed.length > MAX_CANONICAL_STRING_LENGTH) return null
  const at = trimmed.lastIndexOf('@')
  if (at >= 0) {
    const local = trimmed.slice(0, at)
    const host = trimmed.slice(at + 1).toLowerCase()
    if (local.length === 0 || host.length === 0) return null
    return `${local}@${host}`
  }
  return trimmed.toLowerCase()
}

function normalizeSipToken(raw: string): string | null {
  const trimmed = raw.trim()
  if (trimmed.length === 0 || trimmed.length > MAX_CANONICAL_STRING_LENGTH) return null
  return trimmed.toLowerCase()
}

function normalizeSipUser(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase()
  if (trimmed.length === 0 || trimmed.length > MAX_CANONICAL_STRING_LENGTH) return null
  return trimmed
}
