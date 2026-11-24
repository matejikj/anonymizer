/**
 * HTTP discovery/sanitization over reassembled TCP buffers (enterprise step 3).
 */

import { PatchCollector } from '../sanitize/PatchCollector'
import { SessionMapping, type MappingLike } from '../anonymization/mapping'
import { FingerprintSession } from '../anonymization/fingerprintSession'
import type { BytePatch, LayerCoverage } from '../sanitize/types'
import { IntentCollector } from '../discovery/intentCollector'
import type { TransformationIntent } from '../discovery/types'
import { sanitizeHttp, looksLikeHttpBuffer } from '../sanitize/http'
import { looksLikeSbi, sanitizeSbi5g } from '../sanitize/sbi5g'
import type { ByteProvenance, PacketReassemblyOverlay, ReassembledView } from './types'
import {
  mergeProjectedPatches,
  projectEntityIntent,
  projectPatches,
} from './patchProject'

export function processHttpOverReassembledView(
  view: ReassembledView,
  primaryPacketIndex: number,
  payloadOffsetOnPrimary: number,
): Map<number, PacketReassemblyOverlay> {
  const overlays = new Map<number, PacketReassemblyOverlay>()
  if (view.bytes.length === 0 || !looksLikeHttpBuffer(view.bytes)) {
    return overlays
  }

  const intents = new IntentCollector()
  const collector = new PatchCollector(view.bytes.length)
  const mapping = new SessionMapping()
  const httpResult = sanitizeReassembledHttpPayload(
    view.bytes,
    collector,
    mapping,
    intents,
    primaryPacketIndex,
  )
  if (!httpResult) return overlays

  const assembledCoverage: LayerCoverage[] = httpResult.coverage

  const projectedIntents: Array<{ packetIndex: number; intent: TransformationIntent }> = []
  for (const intent of intents.intents) {
    if (intent.kind === 'entity-replacement') {
      projectedIntents.push(...projectEntityIntent(view.provenance, intent))
    } else if (intent.kind === 'mask-range' || intent.kind === 'fixed-redaction') {
      const end = intent.offset + intent.byteLength
      for (const span of view.provenance) {
        const spanEnd = span.assembledOffset + span.length
        const overlapStart = Math.max(intent.offset, span.assembledOffset)
        const overlapEnd = Math.min(end, spanEnd)
        if (overlapStart >= overlapEnd) continue
        const localSpanStart = overlapStart - span.assembledOffset
        const overlapLen = overlapEnd - overlapStart
        projectedIntents.push({
          packetIndex: span.packetIndex,
          intent: {
            ...intent,
            packetIndex: span.packetIndex,
            offset: span.packetOffset + localSpanStart,
            byteLength: overlapLen,
          },
        })
      }
    } else {
      projectedIntents.push({ packetIndex: intent.packetIndex, intent })
    }
  }

  const intentsByPacket = new Map<number, TransformationIntent[]>()
  for (const { packetIndex, intent } of projectedIntents) {
    const list = intentsByPacket.get(packetIndex) ?? []
    list.push(intent)
    intentsByPacket.set(packetIndex, list)
  }

  for (const packetIndex of view.packetIndices) {
    overlays.set(packetIndex, {
      patches: [],
      coverage: assembledCoverage
        .map((c) => ({
          ...c,
          offset: projectCoverageOffset(view.provenance, c.offset, packetIndex, payloadOffsetOnPrimary),
        }))
        .filter((c) => c.length > 0),
      issues: [],
      drop: false,
      intents: intentsByPacket.get(packetIndex) ?? [],
      skipAppLayer: true,
    })
  }

  return overlays
}

export function sanitizeHttpReassembledView(
  view: ReassembledView,
  mapping: MappingLike,
  payloadTime?: import('../kernel/payloadTimeCodec').PayloadTimeSession,
): Map<number, BytePatch[]> {
  if (view.status !== 'complete' || view.bytes.length === 0) return new Map()
  if (!looksLikeHttpBuffer(view.bytes)) return new Map()

  const collector = new PatchCollector(view.bytes.length)
  const intents = new IntentCollector()
  const result = sanitizeReassembledHttpPayload(
    view.bytes,
    collector,
    mapping,
    intents,
    view.packetIndices[0] ?? 0,
  )
  if (!result) return new Map()
  // T14 — payloadTime required for HTTP Date/Last-Modified capture-aligned rewrite.
  collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession(), payloadTime })
  return mergeProjectedPatches(projectPatches(view.provenance, collector.getPatches()))
}

/** T61 — 5G SBI shares TCP/HTTP reassembly; prefer schema-aware sanitizer over generic HTTP. */
function sanitizeReassembledHttpPayload(
  bytes: Uint8Array,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector,
  packetIndex: number,
) {
  if (looksLikeSbi(bytes, 0, bytes.length)) {
    return sanitizeSbi5g(bytes, 0, bytes.length, collector, mapping, intents, packetIndex)
  }
  return sanitizeHttp(bytes, 0, bytes.length, collector, mapping, intents, packetIndex)
}

function projectCoverageOffset(
  provenance: readonly ByteProvenance[],
  assembledOffset: number,
  packetIndex: number,
  fallback: number,
): number {
  for (const span of provenance) {
    if (span.packetIndex !== packetIndex) continue
    if (assembledOffset >= span.assembledOffset && assembledOffset < span.assembledOffset + span.length) {
      return span.packetOffset + (assembledOffset - span.assembledOffset)
    }
  }
  return fallback
}
