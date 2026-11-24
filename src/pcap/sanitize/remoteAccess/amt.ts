/**
 * T39 — Intel AMT (TCP 16992–16995): reuse HTTP sanitizer for digest Authorization redaction.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { looksLikeHttpBuffer, sanitizeHttp } from '../http.ts'

export const AMT_PORTS = new Set([16_992, 16_993, 16_994, 16_995])

export function isAmtPortHint(srcPort: number, dstPort: number): boolean {
  return AMT_PORTS.has(srcPort) || AMT_PORTS.has(dstPort)
}

export function sanitizeAmtHttp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
  highPrivacy = false,
): AppLayerResult | null {
  if (!isAmtPortHint(srcPort, dstPort)) return null
  if (!looksLikeHttpBuffer(buffer, offset, length)) return null
  const http = sanitizeHttp(
    buffer,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
    highPrivacy,
  )
  if (!http) return null
  return {
    coverage: http.coverage.map((c) =>
      c.protocol === 'http' || c.protocol.startsWith('http')
        ? { ...c, protocol: c.protocol === 'http' ? 'amt-http' : `amt-${c.protocol}` }
        : c
    ),
    issues: http.issues,
  }
}
