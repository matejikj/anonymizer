/**
 * T18 — WS-Discovery (UDP 3702): SOAP XML — map urn:uuid / URL / scopes via detectors.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { maskPayloadSpan } from '../protocols/application/textproto'

const WSD_PORTS = new Set([3702])

export function isWsDiscoveryPortHint(src: number, dst: number): boolean {
  return WSD_PORTS.has(src) || WSD_PORTS.has(dst)
}

export function looksLikeWsDiscovery(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 32) return false
  const head = new TextDecoder('latin1').decode(data.subarray(offset, offset + Math.min(length, 256)))
  // SOAP / WS-Discovery without DTD
  if (/<!DOCTYPE/i.test(head) || /<!ENTITY/i.test(head)) return false
  return (
    /Envelope/i.test(head)
    && (/Probe|Resolve|Hello|Bye|wsa:|wsd:/i.test(head) || /schemas\.xmlsoap\.org/i.test(head))
  )
}

export function sanitizeWsDiscovery(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeWsDiscovery(buffer, offset, length)) return null

  const text = new TextDecoder('latin1').decode(buffer.subarray(offset, offset + length))
  if (/<!DOCTYPE/i.test(text) || /<!ENTITY/i.test(text)) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, 'wsd-xxe-reject')
    return {
      coverage: [{ protocol: 'ws-discovery', offset, length, status: 'malformed' }],
      issues: ['wsd-dtd-forbidden'],
    }
  }

  // T63 — until free-text allowlist (T69), fail-closed mask of entire SOAP
  // (Scopes / free text). UUID + detector mapping returns with T69.
  void text
  void mapping
  maskPayloadSpan(collector, offset, length, intents, packetIndex, 'wsd-interim-mask')

  const coverage: LayerCoverage[] = [{
    protocol: 'ws-discovery',
    offset,
    length,
    status: 'redacted',
  }]
  return { coverage, issues: [] }
}
