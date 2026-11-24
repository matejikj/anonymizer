/**
 * T15 / T69 — sanitize a free-text / text/* payload span.
 *
 * Allowlist-first (T69): structure + vocabulary preserved; typed values and
 * free-token mapped; high-privacy unknown words masked. Auth tokens and SIP
 * display-name spans stay fail-closed masks.
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector'
import type { IntentCollector } from '../../../discovery/intentCollector'
import type { MappingLike } from '../../../anonymization/mapping'
import type { CoverageStatus } from '../../../sanitize/types'
import type { IdentityRegistry } from '../../../../mapping/identityRegistry'
import {
  defaultFreeTextVocabulary,
  sanitizeFreeText,
  type FreeTextLevel,
} from '../../../../engine/freeText/index.ts'
import { findEncodedAuthTokenSpans, maskEncodedAuthTokens } from './encodedTokens'
import { maskPayloadSpan } from './applyPayloadMaps'
import { applyFreeTextOpsToCollector } from './applyFreeTextOps'

export interface SanitizeTextPayloadResult {
  readonly hitCount: number
  readonly coverageStatus: CoverageStatus
}

/** Embedded name-addr values in logs; delimiters only count outside quoted strings. */
function sipDisplaySpans(text: string): Array<{ offset: number; length: number }> {
  const spans: Array<{ offset: number; length: number }> = []
  let valueStart = 0
  let inQuote = false
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!
    if (inQuote) {
      if (ch === '\\' && i + 1 < text.length && !/[\r\n]/.test(text[i + 1]!)) i++
      else if (ch === '"') inQuote = false
      else if (ch === '\r' || ch === '\n') { inQuote = false; valueStart = i + 1 }
      continue
    }
    if (ch === '"') { inQuote = true; continue }
    if (ch === '<' && /^<sips?:/i.test(text.slice(i, i + 6))) {
      let start = valueStart
      let end = i
      while (start < end && /[ \t]/.test(text[start]!)) start++
      while (end > start && /[ \t]/.test(text[end - 1]!)) end--
      if (text[start] === '"' && text[end - 1] === '"') { start++; end-- }
      if (start < end) spans.push({ offset: start, length: end - start })
      // URI parameters and punctuation must not become a subsequent display name.
      while (i + 1 < text.length && !/[>\r\n]/.test(text[i + 1]!)) i++
      if (text[i + 1] === '>') i++
      valueStart = i + 1
    } else if ('=,:;[]{}>\r\n'.includes(ch)) {
      valueStart = i + 1
    }
  }
  return spans
}

/**
 * Free-text / text/* payload sanitization (T69 allowlist).
 * Returns `covered` when the span was processed; `redacted` only for non-latin1
 * full-span mask (undecodable).
 */
export function sanitizeTextPayload(input: {
  readonly buffer: Uint8Array
  readonly absoluteOffset: number
  readonly byteLength: number
  readonly collector: PatchCollector
  readonly mapping: MappingLike
  readonly intents?: IntentCollector
  readonly packetIndex: number
  readonly highPrivacy?: boolean
  readonly protocolId?: string
  readonly registry?: IdentityRegistry | null
}): SanitizeTextPayloadResult {
  const {
    buffer,
    absoluteOffset,
    byteLength,
    collector,
    mapping,
    intents,
    packetIndex,
    highPrivacy = false,
    protocolId = 'textproto',
    registry = null,
  } = input

  if (byteLength <= 0) {
    return { hitCount: 0, coverageStatus: 'covered' }
  }

  const slice = buffer.subarray(absoluteOffset, absoluteOffset + byteLength)
  const text = new TextDecoder('latin1').decode(slice)
  if (text.length !== byteLength) {
    maskPayloadSpan(collector, absoluteOffset, byteLength, intents, packetIndex, `${protocolId}-non-latin1`)
    return { hitCount: 0, coverageStatus: 'redacted' }
  }

  const displaySpans = sipDisplaySpans(text)
  for (const span of displaySpans) {
    maskPayloadSpan(
      collector,
      absoluteOffset + span.offset,
      span.length,
      intents,
      packetIndex,
      `${protocolId}-sip-display`,
    )
  }

  const authSpans = findEncodedAuthTokenSpans(text, absoluteOffset)
  maskEncodedAuthTokens(collector, authSpans)

  const skipRanges = [
    ...displaySpans.map((s) => ({ start: s.offset, end: s.offset + s.length })),
    ...authSpans.map((s) => ({
      start: s.absoluteOffset - absoluteOffset,
      end: s.absoluteOffset - absoluteOffset + s.byteLength,
    })),
  ]

  const level: FreeTextLevel = highPrivacy ? 'high-privacy' : 'diagnostic'
  const ops = sanitizeFreeText({
    text,
    level,
    vocabulary: defaultFreeTextVocabulary(),
    registry,
    skipRanges,
  })

  const applied = applyFreeTextOpsToCollector({
    ops,
    absoluteOffset,
    collector,
    mapping,
    intents,
    packetIndex,
    protocolId,
  })

  return {
    hitCount: applied.mapCount + applied.maskCount + displaySpans.length + authSpans.length,
    coverageStatus: 'covered',
  }
}
