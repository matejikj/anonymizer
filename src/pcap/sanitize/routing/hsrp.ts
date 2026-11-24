/**
 * T38 — HSRP v1/v2 (UDP 1985) and GLBP (UDP 3222). Virtual IP mapped; auth masked.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { mapIpv4At, maskBytes } from './common.ts'

export const HSRP_UDP_PORT = 1985
export const GLBP_UDP_PORT = 3222

export function sanitizeHsrpGlbp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (dstPort === HSRP_UDP_PORT) return sanitizeHsrp(buffer, offset, length, collector, mapping, packetIndex, intents)
  if (dstPort === GLBP_UDP_PORT) return sanitizeGlbp(buffer, offset, length, collector, mapping, packetIndex, intents)
  return null
}

function sanitizeHsrp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): AppLayerResult {
  const coverage: AppLayerResult['coverage'] = []
  if (length < 20) {
    return { coverage: [{ protocol: 'hsrp', offset, length, status: 'malformed' }] }
  }
  const version = buffer[offset]!
  // v1: op(1) state(1) hellotime(1) holdtime(1) priority(1) group(1) reserved(1) auth(8) vip(4)
  if (version === 0 && length >= 20) {
    maskBytes(collector, intents, packetIndex, offset + 8, 8, 'hsrp-auth', 'hsrp')
    coverage.push({ protocol: 'hsrp-auth', offset: offset + 8, length: 8, status: 'redacted' })
    mapIpv4At(buffer, offset + 16, collector, mapping, intents, packetIndex, 'hsrp')
    coverage.push({ protocol: 'hsrp', offset, length: 20, status: 'covered' })
    if (length > 20) {
      maskBytes(collector, intents, packetIndex, offset + 20, length - 20, 'hsrp-tail', 'hsrp')
      coverage.push({
        protocol: 'hsrp-body',
        offset: offset + 20,
        length: length - 20,
        status: 'redacted',
      })
    }
    return { coverage }
  }
  // v2 / unknown layout — fail-closed mask of body (auth may be anywhere)
  coverage.push({ protocol: 'hsrp', offset, length: Math.min(4, length), status: 'covered' })
  if (length > 4) {
    maskBytes(collector, intents, packetIndex, offset + 4, length - 4, 'hsrp-body', 'hsrp')
    coverage.push({
      protocol: 'hsrp-body',
      offset: offset + 4,
      length: length - 4,
      status: 'redacted',
    })
  }
  return { coverage }
}

function sanitizeGlbp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): AppLayerResult {
  const coverage: AppLayerResult['coverage'] = []
  if (length < 12) {
    return { coverage: [{ protocol: 'glbp', offset, length, status: 'malformed' }] }
  }
  coverage.push({ protocol: 'glbp', offset, length: 12, status: 'covered' })
  if (length > 12) {
    // Mask TLV/auth body; map trailing 4 bytes as VIP when present (common layout).
    const bodyLen = length - 12
    if (bodyLen >= 4) {
      mapIpv4At(buffer, offset + length - 4, collector, mapping, intents, packetIndex, 'glbp')
      if (bodyLen > 4) {
        maskBytes(collector, intents, packetIndex, offset + 12, bodyLen - 4, 'glbp-auth', 'glbp')
      }
    } else {
      maskBytes(collector, intents, packetIndex, offset + 12, bodyLen, 'glbp-body', 'glbp')
    }
    coverage.push({
      protocol: 'glbp-body',
      offset: offset + 12,
      length: bodyLen,
      status: 'redacted',
    })
  }
  return { coverage }
}
