/**
 * T15 — apply payload detector / extractor hits as length-preserving map patches.
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector'
import type { IntentCollector } from '../../../discovery/intentCollector'
import type { MappingLike } from '../../../anonymization/mapping'
import { computeFixedLengthAsciiBytes, patchFixedLengthAscii } from '../../../sanitize/textPatch'
import type { IdentityCategory } from '../../../../mapping/identityCategories'
import type { PayloadDetectorHit } from './payloadDetectors'
import type { TextProtoExtractedValue } from './extractors'

export interface PayloadMapHit {
  readonly category: IdentityCategory
  readonly absoluteOffset: number
  readonly byteLength: number
  readonly originalSpelling: string
  readonly canonical: string
}

export function hitsFromDetectors(hits: readonly PayloadDetectorHit[]): PayloadMapHit[] {
  return hits.map((h) => ({
    category: h.category,
    absoluteOffset: h.absoluteOffset,
    byteLength: h.byteLength,
    originalSpelling: h.originalSpelling,
    canonical: h.canonical,
  }))
}

export function hitsFromExtractors(hits: readonly TextProtoExtractedValue[]): PayloadMapHit[] {
  return hits.map((h) => ({
    category: h.category,
    absoluteOffset: h.absoluteOffset,
    byteLength: h.byteLength,
    originalSpelling: h.originalSpelling,
    canonical: h.canonical,
  }))
}

/**
 * Schedule deferred length-preserving maps. On length mismatch → mask fill (never original).
 */
export function applyPayloadMapHits(
  hits: readonly PayloadMapHit[],
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolId = 'textproto',
): void {
  void _mapping
  for (const hit of hits) {
    if (hit.byteLength <= 0) continue
    const constraint = { kind: 'text-ascii' as const, byteLength: hit.byteLength }
    intents?.recordEntityReplacement(
      packetIndex,
      hit.absoluteOffset,
      hit.category,
      hit.canonical,
      hit.byteLength,
      constraint,
      hit.originalSpelling,
    )
    collector.addDeferred(hit.absoluteOffset, hit.byteLength, ({ mapping: live }) => {
      try {
        const mapped = live.aliasFor(
          hit.category,
          hit.canonical,
          constraint,
          hit.originalSpelling,
        )
        if (mapped.length !== hit.byteLength) {
          return computeFixedLengthAsciiBytes(hit.absoluteOffset, hit.byteLength, '', 0x78)
        }
        return computeFixedLengthAsciiBytes(hit.absoluteOffset, hit.byteLength, mapped)
      } catch {
        return computeFixedLengthAsciiBytes(hit.absoluteOffset, hit.byteLength, '', 0x78)
      }
    }, {
      fallbackKind: 'text-x',
      protocol: protocolId,
      category: String(hit.category),
      packetIndex,
    })
  }
}

/** Mask a whole span (high-privacy unmatched free text). */
export function maskPayloadSpan(
  collector: PatchCollector,
  absoluteOffset: number,
  byteLength: number,
  intents: IntentCollector | undefined,
  packetIndex: number,
  reason = 'textproto-free-text',
): void {
  if (byteLength <= 0) return
  patchFixedLengthAscii(collector, absoluteOffset, byteLength, '', 0x78)
  intents?.recordMaskRange(packetIndex, absoluteOffset, byteLength, reason, 'textproto')
}
