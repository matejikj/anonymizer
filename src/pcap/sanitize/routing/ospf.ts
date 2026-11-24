/**
 * T38 — OSPFv2 (IP proto 89). Header + auth; unknown LSA body masked (not full LSA dictionary).
 * RFC 2328.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import { mapRouterId, maskBytes, readU16 } from './common.ts'

export const IPPROTO_OSPF = 89

export function sanitizeOspf(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; lastCoveredOffset: number } {
  const coverage: LayerCoverage[] = []
  const len = data.length - offset
  if (len < 24) {
    coverage.push({ protocol: 'ospf', offset, length: len, status: 'malformed' })
    return { coverage, lastCoveredOffset: offset }
  }
  const version = data[offset]!
  if (version !== 2 && version !== 3) {
    coverage.push({ protocol: 'ospf', offset, length: len, status: 'unsupported' })
    return { coverage, lastCoveredOffset: offset }
  }

  const pktLen = readU16(data, offset + 2)
  const end = offset + Math.min(len, pktLen > 0 ? pktLen : len)

  // Router ID (4), Area ID (4)
  mapRouterId(data, offset + 4, 'ospf', collector, mapping, intents, packetIndex, 'ospf')
  const area = `${data[offset + 8]!}.${data[offset + 9]!}.${data[offset + 10]!}.${data[offset + 11]!}`
  if (area !== '0.0.0.0') {
    mapRouterId(data, offset + 8, 'ospf-area', collector, mapping, intents, packetIndex, 'ospf')
  }

  if (version === 2) {
    const auType = readU16(data, offset + 14)
    // Auth data at offset+16, 8 bytes
    if (auType === 1 || auType === 2) {
      maskBytes(collector, intents, packetIndex, offset + 16, 8, 'ospf-auth', 'ospf')
      coverage.push({ protocol: 'ospf-auth', offset: offset + 16, length: 8, status: 'redacted' })
    }
  }

  coverage.push({ protocol: 'ospf', offset, length: 24, status: 'covered' })

  // Remainder (LSAs / Hello neighbors / v3 auth trailer): fail-closed mask — not a full LSA walk.
  if (end > offset + 24) {
    const bodyOff = offset + 24
    const bodyLen = end - bodyOff
    maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, 'ospf-body', 'ospf')
    coverage.push({ protocol: 'ospf-body', offset: bodyOff, length: bodyLen, status: 'redacted' })
    return { coverage, lastCoveredOffset: end }
  }
  return { coverage, lastCoveredOffset: offset + 24 }
}
