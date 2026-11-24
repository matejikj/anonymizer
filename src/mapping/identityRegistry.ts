/**
 * T66 — IdentityRegistry: projection of MappingAuthority snapshot for cross-protocol
 * free-text propagation. Holds only propagatable identities (length ≥ 4, not B2).
 * Never embeds originals into reports — registry is plan-time / export-time only.
 */

import type { IdentityCategory } from './identityCategories'
import { isCommonWordAllowlisted } from './commonWordAllowlist'
import type { MappingSnapshot, MappingSnapshotEntry } from './types'

const MIN_SPELLING = 4

/** Categories whose string forms are safe/useful to hunt in free text. */
const PROPAGATABLE = new Set<string>([
  'sip-user',
  'sip-phone',
  'sip-token',
  'hostname',
  'email',
  'person',
  'user-id',
  'internal-id',
  'opaque-id',
  'radioId',
  'ssid',
  'custom',
  // IPs as text (SIP URIs, logs) — binary forms stay with T65
  'ipv4',
  'ip',
])

export interface PropagatableIdentity {
  readonly category: IdentityCategory
  readonly canonical: string
  /** Primary alias from the snapshot (may need length adaptation per hit). */
  readonly alias: string
  readonly spellings: readonly string[]
}

export interface IdentityHit {
  readonly start: number
  readonly end: number
  readonly spelling: string
  readonly identity: PropagatableIdentity
}

function latin1Bytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length)
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff
  return out
}

function isTokenBoundary(code: number): boolean {
  // Alphanumeric + underscore stay inside a token.
  return !(
    (code >= 0x30 && code <= 0x39)
    || (code >= 0x41 && code <= 0x5a)
    || (code >= 0x61 && code <= 0x7a)
    || code === 0x5f
  )
}

function collectSpellings(entry: MappingSnapshotEntry): string[] {
  const out: string[] = []
  const push = (s: string) => {
    const t = s.trim()
    if (t.length < MIN_SPELLING) return
    if (isCommonWordAllowlisted(t)) return
    out.push(t)
  }
  push(entry.canonical)
  // Alias itself is never searched — we only hunt originals / canonicals.
  return out
}

export class IdentityRegistry {
  private readonly identities: readonly PropagatableIdentity[]
  /** Lowercase spelling → identity (longest spelling wins on conflicts). */
  private readonly byLowerSpelling: ReadonlyMap<string, PropagatableIdentity>
  private readonly needlesDesc: readonly string[]

  private constructor(identities: readonly PropagatableIdentity[]) {
    this.identities = identities
    const map = new Map<string, PropagatableIdentity>()
    for (const id of identities) {
      for (const sp of id.spellings) {
        const key = sp.toLowerCase()
        const prev = map.get(key)
        if (!prev) {
          map.set(key, id)
        }
      }
    }
    this.byLowerSpelling = map
    this.needlesDesc = [...map.keys()].sort((a, b) => b.length - a.length)
  }

  static fromMappingSnapshot(snapshot: MappingSnapshot): IdentityRegistry {
    const identities: PropagatableIdentity[] = []
    for (const entry of snapshot.entries) {
      if (!PROPAGATABLE.has(entry.category)) continue
      if (!entry.alias || entry.alias.length === 0) continue
      const spellings = collectSpellings(entry)
      if (spellings.length === 0) continue
      identities.push({
        category: entry.category,
        canonical: entry.canonical,
        alias: entry.alias,
        spellings,
      })
    }
    return new IdentityRegistry(identities)
  }

  get size(): number {
    return this.identities.length
  }

  list(): readonly PropagatableIdentity[] {
    return this.identities
  }

  /**
   * Case-insensitive, token-bounded scan of a UTF-16 JS string (text logs).
   * Longer spellings are preferred when overlaps occur.
   */
  findHitsInText(text: string): readonly IdentityHit[] {
    if (this.needlesDesc.length === 0 || text.length === 0) return []
    const lower = text.toLowerCase()
    const hits: IdentityHit[] = []
    const claimed = new Uint8Array(text.length)

    for (const needle of this.needlesDesc) {
      const identity = this.byLowerSpelling.get(needle)
      if (!identity) continue
      let from = 0
      while (from <= lower.length - needle.length) {
        const idx = lower.indexOf(needle, from)
        if (idx < 0) break
        const end = idx + needle.length
        const beforeOk = idx === 0 || isTokenBoundary(text.charCodeAt(idx - 1))
        const afterOk = end >= text.length || isTokenBoundary(text.charCodeAt(end))
        let overlap = false
        if (beforeOk && afterOk) {
          for (let i = idx; i < end; i++) {
            if (claimed[i]) {
              overlap = true
              break
            }
          }
          if (!overlap) {
            for (let i = idx; i < end; i++) claimed[i] = 1
            hits.push({
              start: idx,
              end,
              spelling: text.slice(idx, end),
              identity,
            })
          }
        }
        from = idx + 1
      }
    }

    return hits.sort((a, b) => a.start - b.start)
  }

  /**
   * Case-insensitive latin1 byte scan (PCAP payloads). Token boundaries use byte values.
   */
  findHitsInBytes(haystack: Uint8Array): readonly IdentityHit[] {
    if (this.needlesDesc.length === 0 || haystack.length === 0) return []

    const lower = new Uint8Array(haystack.length)
    for (let i = 0; i < haystack.length; i++) {
      const b = haystack[i]!
      lower[i] = b >= 0x41 && b <= 0x5a ? b + 0x20 : b
    }

    const claimed = new Uint8Array(haystack.length)
    const out: IdentityHit[] = []

    for (const needle of this.needlesDesc) {
      const identity = this.byLowerSpelling.get(needle)
      if (!identity) continue
      const needleBytes = latin1Bytes(needle)
      let from = 0
      while (from <= lower.length - needleBytes.length) {
        const idx = indexOfBytes(lower, needleBytes, from)
        if (idx < 0) break
        const end = idx + needleBytes.length
        const beforeOk = idx === 0 || isTokenBoundary(haystack[idx - 1]!)
        const afterOk = end >= haystack.length || isTokenBoundary(haystack[end]!)
        let overlap = false
        if (beforeOk && afterOk) {
          for (let i = idx; i < end; i++) {
            if (claimed[i]) {
              overlap = true
              break
            }
          }
          if (!overlap) {
            for (let i = idx; i < end; i++) claimed[i] = 1
            let spelling = ''
            for (let i = idx; i < end; i++) spelling += String.fromCharCode(haystack[i]!)
            out.push({ start: idx, end, spelling, identity })
          }
        }
        from = idx + 1
      }
    }

    return out.sort((a, b) => a.start - b.start)
  }
}

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array, from: number): number {
  outer: for (let i = from; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer
    }
    return i
  }
  return -1
}
