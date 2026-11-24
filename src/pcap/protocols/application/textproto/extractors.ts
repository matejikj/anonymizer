/**
 * T15 — value extractors returning spans + identity categories (no aliases).
 */

import type { IdentityCategory } from '../../../../mapping/identityCategories'
import { canonicalizeIdentity } from '../../../../mapping/canonicalize'
import { normalizeIpv4Canonical, normalizeIpv6Canonical } from '../../../../mapping/sharedNormalize'

export interface TextProtoExtractedValue {
  readonly category: IdentityCategory
  /** Absolute offset into the parent buffer. */
  readonly absoluteOffset: number
  readonly byteLength: number
  readonly originalSpelling: string
  readonly canonical: string
}

/**
 * Extract host / IP / email / phone-shaped tokens from a header or free-text value.
 * Offsets are relative to `absoluteBase` (start of `text` in the parent buffer).
 */
export function extractTextProtoValues(
  text: string,
  absoluteBase: number,
): readonly TextProtoExtractedValue[] {
  const out: TextProtoExtractedValue[] = []
  if (text.length === 0) return out

  // scheme://[user@]host[:port]/path
  const uriRe = /\b([a-z][a-z0-9+.-]*):\/\/(?:([^/@\s]+)@)?(\[[0-9a-fA-F:.]+\]|[^/:?\s]+)(?::(\d{1,5}))?/gi
  let m: RegExpExecArray | null
  while ((m = uriRe.exec(text)) !== null) {
    const hostRaw = m[3]!
    const hostStartInMatch = m[0]!.indexOf(hostRaw)
    pushHost(out, hostRaw, absoluteBase + m.index + hostStartInMatch)
    const user = m[2]
    if (user) {
      const userStart = m[0]!.indexOf(user)
      pushUserOrPhone(out, user, absoluteBase + m.index + userStart)
    }
  }

  // user@host (email or AAA) — mailbox when domain has a dot
  const atRe = /\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g
  while ((m = atRe.exec(text)) !== null) {
    const spelling = m[0]!
    const canon = canonicalizeIdentity('email', spelling)
    if (canon) {
      out.push({
        category: 'email',
        absoluteOffset: absoluteBase + m.index,
        byteLength: spelling.length,
        originalSpelling: spelling,
        canonical: canon,
      })
    }
  }

  // Bare IPv4
  const ipv4Re = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g
  while ((m = ipv4Re.exec(text)) !== null) {
    pushHost(out, m[1]!, absoluteBase + m.index)
  }

  // +E.164 phone
  const phoneRe = /\+\d{8,15}\b/g
  while ((m = phoneRe.exec(text)) !== null) {
    const spelling = m[0]!
    const canon = canonicalizeIdentity('sip-phone', spelling)
    if (canon) {
      out.push({
        category: 'sip-phone',
        absoluteOffset: absoluteBase + m.index,
        byteLength: spelling.length,
        originalSpelling: spelling,
        canonical: canon,
      })
    }
  }

  return dedupeOverlaps(out)
}

function pushHost(out: TextProtoExtractedValue[], raw: string, abs: number): void {
  const host = raw.startsWith('[') && raw.endsWith(']') ? raw.slice(1, -1) : raw
  const v6 = normalizeIpv6Canonical(host)
  if (v6) {
    out.push({
      category: 'ipv6',
      absoluteOffset: abs,
      byteLength: raw.length,
      originalSpelling: raw,
      canonical: v6,
    })
    return
  }
  const v4 = normalizeIpv4Canonical(host)
  if (v4) {
    out.push({
      category: 'ipv4',
      absoluteOffset: abs,
      byteLength: raw.length,
      originalSpelling: raw,
      canonical: v4,
    })
    return
  }
  const hn = canonicalizeIdentity('hostname', host.toLowerCase())
  if (hn && host.includes('.')) {
    out.push({
      category: 'hostname',
      absoluteOffset: abs,
      byteLength: raw.length,
      originalSpelling: raw,
      canonical: hn,
    })
  }
}

function pushUserOrPhone(out: TextProtoExtractedValue[], user: string, abs: number): void {
  if (user.startsWith('+')) {
    const canon = canonicalizeIdentity('sip-phone', user)
    if (canon) {
      out.push({
        category: 'sip-phone',
        absoluteOffset: abs,
        byteLength: user.length,
        originalSpelling: user,
        canonical: canon,
      })
      return
    }
  }
  const canon = canonicalizeIdentity('user-id', user)
  if (canon) {
    out.push({
      category: 'user-id',
      absoluteOffset: abs,
      byteLength: user.length,
      originalSpelling: user,
      canonical: canon,
    })
  }
}

function dedupeOverlaps(items: TextProtoExtractedValue[]): TextProtoExtractedValue[] {
  const sorted = [...items].sort((a, b) => a.absoluteOffset - b.absoluteOffset || b.byteLength - a.byteLength)
  const kept: TextProtoExtractedValue[] = []
  for (const item of sorted) {
    const overlaps = kept.some(
      (k) =>
        item.absoluteOffset < k.absoluteOffset + k.byteLength
        && k.absoluteOffset < item.absoluteOffset + item.byteLength,
    )
    if (!overlaps) kept.push(item)
  }
  return kept
}
