/**
 * T18 — LLMNR (UDP/TCP 5355): DNS-shaped messages via shared sanitizeDns.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { sanitizeDns } from './dns'

const LLMNR_PORTS = new Set([5355])

export function isLlmnrPortHint(src: number, dst: number): boolean {
  return LLMNR_PORTS.has(src) || LLMNR_PORTS.has(dst)
}

export function looksLikeLlmnr(_data: Uint8Array, _offset: number, length: number): boolean {
  return length >= 12
}

export function sanitizeLlmnr(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  transport: 'udp' | 'tcp',
): AppLayerResult | null {
  if (!looksLikeLlmnr(buffer, offset, length)) return null

  let dnsOffset = offset
  let dnsLength = length
  if (transport === 'tcp' && length > 2) {
    const msgLen = (buffer[offset]! << 8) | buffer[offset + 1]!
    if (msgLen + 2 > length) {
      return {
        coverage: [{ protocol: 'llmnr', offset, length, status: 'requires-reassembly' }],
        issues: ['llmnr-tcp-incomplete'],
      }
    }
    dnsOffset = offset + 2
    dnsLength = msgLen
  }

  const ok = sanitizeDns(buffer, dnsOffset, dnsLength, collector, mapping, intents, packetIndex)
  const coverage: LayerCoverage[] = [{
    protocol: 'llmnr',
    offset,
    length,
    status: ok ? 'covered' : 'malformed',
  }]
  return { coverage, issues: ok ? [] : ['llmnr-malformed'] }
}
