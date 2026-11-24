/**
 * T38 — IGMPv2/v3 (IP proto 2). Map group addresses; mask unknown aux data.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import { mapIpv4At, maskBytes, readU16 } from './common.ts'

export const IPPROTO_IGMP = 2

const WELL_KNOWN = new Set(['224.0.0.1', '224.0.0.2', '224.0.0.22'])

export function sanitizeIgmp(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; lastCoveredOffset: number } {
  const coverage: LayerCoverage[] = []
  const len = data.length - offset
  if (len < 8) {
    coverage.push({ protocol: 'igmp', offset, length: len, status: 'malformed' })
    return { coverage, lastCoveredOffset: offset }
  }
  const type = data[offset]!
  // Group address at offset+4 for v1/v2
  const group = `${data[offset + 4]!}.${data[offset + 5]!}.${data[offset + 6]!}.${data[offset + 7]!}`
  if (!WELL_KNOWN.has(group) && group !== '0.0.0.0') {
    mapIpv4At(data, offset + 4, collector, mapping, intents, packetIndex, 'igmp')
  }
  coverage.push({ protocol: 'igmp', offset, length: 8, status: 'covered' })

  // IGMPv3 Membership Report: type 0x22, more records after header
  if (type === 0x22 && len >= 12) {
    let pos = offset + 8
    const numRecords = readU16(data, offset + 6)
    for (let r = 0; r < numRecords && pos + 8 <= data.length; r++) {
      const aux = data[pos + 1]!
      const numSrc = readU16(data, pos + 2)
      const gOff = pos + 4
      const gText = `${data[gOff]!}.${data[gOff + 1]!}.${data[gOff + 2]!}.${data[gOff + 3]!}`
      if (!WELL_KNOWN.has(gText)) {
        mapIpv4At(data, gOff, collector, mapping, intents, packetIndex, 'igmp')
      }
      pos += 8
      for (let s = 0; s < numSrc && pos + 4 <= data.length; s++) {
        mapIpv4At(data, pos, collector, mapping, intents, packetIndex, 'igmp')
        pos += 4
      }
      if (aux > 0) {
        const auxLen = aux * 4
        if (pos + auxLen <= data.length) {
          maskBytes(collector, intents, packetIndex, pos, auxLen, 'igmp-aux', 'igmp')
          pos += auxLen
        }
      }
    }
    coverage.push({
      protocol: 'igmp-v3',
      offset: offset + 8,
      length: Math.max(0, pos - (offset + 8)),
      status: 'covered',
    })
    return { coverage, lastCoveredOffset: pos }
  }

  if (len > 8) {
    maskBytes(collector, intents, packetIndex, offset + 8, len - 8, 'igmp-tail', 'igmp')
    coverage.push({
      protocol: 'igmp-body',
      offset: offset + 8,
      length: len - 8,
      status: 'redacted',
    })
  }
  return { coverage, lastCoveredOffset: offset + len }
}
