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

  const authSpans = findEncodedAuthTokenSpans(text, absoluteOffset)
  maskEncodedAuthTokens(collector, authSpans)

  const hits = detectIdentitiesInPayload(buffer, absoluteOffset, byteLength)
  applyPayloadMapHits(hitsFromDetectors(hits), collector, mapping, intents, packetIndex, protocolId)

  if (hits.length === 0 && authSpans.length === 0) {
    return { hitCount: 0, coverageStatus: 'heuristic' }
  }
  return {
    hitCount: hits.length + authSpans.length,
    coverageStatus: 'heuristic',
  }
}
