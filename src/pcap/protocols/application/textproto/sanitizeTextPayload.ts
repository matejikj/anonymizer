/**
 * T15 — sanitize a free-text / text/* payload span with detectors + auth-token mask.
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector'
import type { IntentCollector } from '../../../discovery/intentCollector'
import type { MappingLike } from '../../../anonymization/mapping'
import type { CoverageStatus } from '../../../sanitize/types'
import { detectIdentitiesInPayload } from './payloadDetectors'
import { findEncodedAuthTokenSpans, maskEncodedAuthTokens } from './encodedTokens'
import {
  applyPayloadMapHits,
  hitsFromDetectors,
  maskPayloadSpan,
} from './applyPayloadMaps'

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
 * Diagnostic: map detector hits + mask auth tokens; unmatched text stays (heuristic).
 * High-privacy: after maps/tokens, mask the entire span (fail-closed free text).
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

  // High-privacy: free text without schema → full mask (T15 / T14 §2).
  if (highPrivacy) {
    maskPayloadSpan(collector, absoluteOffset, byteLength, intents, packetIndex, `${protocolId}-high-privacy`)
    return { hitCount: 0, coverageStatus: 'redacted' }
  }

  // SIP name-addr display text is a separate identity from the URI user. Logs can
  // repeat a phone number here even after the URI itself has been mapped.
  const displaySpans = sipDisplaySpans(text).map(span => ({ ...span, offset: absoluteOffset + span.offset }))
  for (const span of displaySpans) {
    maskPayloadSpan(collector, span.offset, span.length, intents, packetIndex, `${protocolId}-sip-display`)
  }

  const authSpans = findEncodedAuthTokenSpans(text, absoluteOffset)
  maskEncodedAuthTokens(collector, authSpans)

  const hits = detectIdentitiesInPayload(buffer, absoluteOffset, byteLength).filter(hit =>
    !displaySpans.some(span => hit.absoluteOffset < span.offset + span.length && hit.absoluteOffset + hit.byteLength > span.offset))
  applyPayloadMapHits(hitsFromDetectors(hits), collector, mapping, intents, packetIndex, protocolId)

  if (hits.length === 0 && authSpans.length === 0) {
    return { hitCount: 0, coverageStatus: 'heuristic' }
  }
  return {
    hitCount: hits.length + authSpans.length,
    coverageStatus: 'heuristic',
  }
}
