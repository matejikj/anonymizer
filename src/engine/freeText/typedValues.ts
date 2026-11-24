/**
 * T69 — typed free-text value detectors (reuse existing identity categories).
 *
 * These are allowlist *reinforcements*: a typed hit is mapped; absence of a hit
 * never means “leave the token” — unclassified words go to free-token / mask.
 */

import type { IdentityCategory } from '../../mapping/identityCategories.ts'

export interface TypedSpan {
  readonly start: number
  readonly end: number
  readonly category: IdentityCategory
  readonly canonical: string
  readonly spelling: string
  /** Always mask (auth-like), never map. */
  readonly forceMask?: boolean
}

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
const MAC_RE = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g
const UUID_RE = /\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b/g
const URL_RE = /\b(?:https?|sips?|wss?):\/\/[^\s<>"']+/gi
const PHONE_RE = /(?<![A-Za-z0-9])\+?\d[\d\s()./-]{7,18}\d(?![A-Za-z0-9])/g
const HEX_ID_RE = /\b[0-9A-Fa-f]{8,64}\b/g
const AUTH_KV_RE = /\b(?:password|passwd|pwd|token|secret|authorization|api[_-]?key)\s*[:=]\s*([^\s,;]+)/gi

function pushNonOverlapping(
  out: TypedSpan[],
  span: TypedSpan,
): void {
  for (const existing of out) {
    if (span.start < existing.end && span.end > existing.start) return
  }
  out.push(span)
}

/**
 * Find typed identity / secret spans in `text`. Results are sorted by start.
 */
export function findTypedSpans(text: string): TypedSpan[] {
  const out: TypedSpan[] = []

  AUTH_KV_RE.lastIndex = 0
  for (let m = AUTH_KV_RE.exec(text); m; m = AUTH_KV_RE.exec(text)) {
    const value = m[1]
    if (!value) continue
    const start = m.index + m[0]!.length - value.length
    pushNonOverlapping(out, {
      start,
      end: start + value.length,
      category: 'opaque-id',
      canonical: value,
      spelling: value,
      forceMask: true,
    })
  }

  const add = (
    re: RegExp,
    category: IdentityCategory,
    canon: (raw: string) => string,
    forceMask = false,
  ) => {
    re.lastIndex = 0
    for (let m = re.exec(text); m; m = re.exec(text)) {
      const spelling = m[0]!
      pushNonOverlapping(out, {
        start: m.index,
        end: m.index + spelling.length,
        category,
        canonical: canon(spelling),
        spelling,
        forceMask,
      })
    }
  }

  add(EMAIL_RE, 'email', (s) => s.toLowerCase())
  add(URL_RE, 'opaque-id', (s) => s)
  add(IPV4_RE, 'ipv4', (s) => s)
  add(MAC_RE, 'mac', (s) => s.toLowerCase().replace(/-/g, ':'))
  add(UUID_RE, 'opaque-id', (s) => s.toLowerCase())
  add(PHONE_RE, 'sip-phone', (s) => s.replace(/[^\d+]/g, ''))
  add(HEX_ID_RE, 'opaque-id', (s) => s.toLowerCase())

  out.sort((a, b) => a.start - b.start || b.end - a.end)
  return out
}

/** Pure digit token classification without surrounding field policy. */
export function classifyDigitToken(text: string): 'preserve' | 'map-opaque' {
  // Short counts / ports stay; longer digit runs are treated as identifiers.
  if (/^\d{1,4}$/.test(text)) return 'preserve'
  return 'map-opaque'
}
