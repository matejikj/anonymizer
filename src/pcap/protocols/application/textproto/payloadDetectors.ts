/**
 * T15 — run text-engine builtin detectors over a PCAP payload span.
 * Aliases are never generated here — callers resolve via MappingAuthority / MappingLike.
 */

import type { Category, DetectorConfig, RawMatch } from '../../../../domain/types'
import { DEFAULT_DETECTOR_CONFIG } from '../../../../domain/types'
import type { RulesetBuiltinToggles } from '../../../../domain/configSchema'
import { DEFAULT_BUILTIN_TOGGLES } from '../../../../domain/configSchema'
import { detectOnPhysicalLine } from '../../../../engine/detectLine'
import { resolveOverlaps } from '../../../../engine/resolveOverlaps'
import type { IdentityCategory } from '../../../../mapping/identityCategories'
import { canonicalizeIdentity } from '../../../../mapping/canonicalize'

export interface PayloadDetectorHit {
  readonly category: IdentityCategory
  readonly absoluteOffset: number
  readonly byteLength: number
  readonly originalSpelling: string
  readonly canonical: string
  readonly detectorId: string
}

export interface PayloadDetectorOptions {
  /** Builtins only — PCAP must not depend on user custom regex rules (T15 open Q). */
  readonly builtins?: RulesetBuiltinToggles
  readonly detectorConfig?: DetectorConfig
  /**
   * When true (high-privacy), unmatched free text should be masked by the caller.
   * This adapter only reports hits; it does not mask.
   */
  readonly highPrivacy?: boolean
}

const CATEGORY_TO_IDENTITY: Partial<Record<Category, IdentityCategory>> = {
  ip: 'ip',
  hostname: 'hostname',
  'sip-phone': 'sip-phone',
  email: 'email',
  person: 'person',
  'user-id': 'user-id',
  'internal-id': 'internal-id',
  port: 'port',
}

/**
 * Detect identities in `buffer[offset, offset+length)` using the same builtins as text logs.
 * Requires Latin-1/ASCII-compatible payload (byteLength === decoded length).
 */
export function detectIdentitiesInPayload(
  buffer: Uint8Array,
  offset: number,
  length: number,
  options: PayloadDetectorOptions = {},
): readonly PayloadDetectorHit[] {
  void options.highPrivacy
  if (length <= 0) return []
  const slice = buffer.subarray(offset, offset + length)
  const text = new TextDecoder('latin1').decode(slice)
  if (text.length !== length) return []

  const builtins = options.builtins ?? DEFAULT_BUILTIN_TOGGLES
  const config = options.detectorConfig ?? DEFAULT_DETECTOR_CONFIG
  // Strip custom rules — PCAP path is builtins + hostname/ID suffixes only.
  const detectorConfig: DetectorConfig = {
    ...config,
    customRules: [],
  }

  const raw: RawMatch[] = []
  let lineStart = 0
  let lineNumber = 1
  for (let i = 0; i <= text.length; i++) {
    const atEnd = i === text.length
    const isNl = !atEnd && (text[i] === '\n' || text[i] === '\r')
    if (!atEnd && !isNl) continue

    let lineEnd = i
    if (!atEnd && text[i] === '\r' && i + 1 < text.length && text[i + 1] === '\n') {
      // CRLF — line content excludes both
    }
    const lineText = text.slice(lineStart, lineEnd)
    if (lineText.length > 0) {
      raw.push(
        ...detectOnPhysicalLine(lineText, lineNumber, offset + lineStart, detectorConfig, builtins),
      )
    }
    if (atEnd) break
    if (text[i] === '\r' && i + 1 < text.length && text[i + 1] === '\n') i++
    lineStart = i + 1
    lineNumber++
  }

  const resolved = resolveOverlaps(raw)
  const hits: PayloadDetectorHit[] = []
  for (const match of resolved) {
    // The PCAP authority uses wire IP namespaces, including for textual representations.
    const identityCat = match.category === 'ip'
      ? (match.normalized.includes(':') ? 'ipv6' : 'ipv4')
      : CATEGORY_TO_IDENTITY[match.category]
    if (!identityCat) continue
    const spelling = match.original
    const byteLength = match.end - match.start
    if (byteLength <= 0 || spelling.length !== byteLength) continue
    const canonical = canonicalizeIdentity(identityCat, spelling)
      ?? canonicalizeIdentity(identityCat, match.normalized)
    if (!canonical) continue
    hits.push({
      category: identityCat,
      absoluteOffset: match.start,
      byteLength,
      originalSpelling: spelling,
      canonical,
      detectorId: match.detectorId,
    })
  }
  return hits
}
