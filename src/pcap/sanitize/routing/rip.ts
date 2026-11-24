/**
 * T38 — RIPv1/v2 / RIPng (UDP 520/521). Auth entries masked; route IPs mapped.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { mapIpv4At, maskBytes, readU16 } from './common.ts'

export const RIP_UDP_PORTS = new Set([520, 521])

export function sanitizeRip(
  buffer: Uint8Array,
  offset: number,
  length: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!RIP_UDP_PORTS.has(dstPort)) return null
  if (length < 4) {
    return { coverage: [{ protocol: 'rip', offset, length, status: 'malformed' }] }
  }

  const coverage: AppLayerResult['coverage'] = []
  coverage.push({ protocol: 'rip', offset, length: 4, status: 'covered' })

  // RIPng (521): mask body after header — IPv6 route dictionary not in this baseline.
  if (dstPort === 521) {
    if (length > 4) {
      maskBytes(collector, intents, packetIndex, offset + 4, length - 4, 'ripng-body', 'rip')
      coverage.push({
        protocol: 'rip-body',
        offset: offset + 4,
        length: length - 4,
        status: 'redacted',
      })
    }
    return { coverage }
  }

  let pos = offset + 4
  const end = offset + length
  while (pos + 20 <= end) {
    const afi = readU16(buffer, pos)
    if (afi === 0xffff) {
      // RIPv2 auth
      maskBytes(collector, intents, packetIndex, pos, 20, 'rip-auth', 'rip')
      coverage.push({ protocol: 'rip-auth', offset: pos, length: 20, status: 'redacted' })
      pos += 20
      continue
    }
    // IPv4 address + mask + next-hop
    mapIpv4At(buffer, pos + 4, collector, mapping, intents, packetIndex, 'rip')
    mapIpv4At(buffer, pos + 8, collector, mapping, intents, packetIndex, 'rip')
    mapIpv4At(buffer, pos + 12, collector, mapping, intents, packetIndex, 'rip')
    coverage.push({ protocol: 'rip-route', offset: pos, length: 20, status: 'covered' })
    pos += 20
  }
  if (pos < end) {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'rip-tail', 'rip')
    coverage.push({ protocol: 'rip-body', offset: pos, length: end - pos, status: 'redacted' })
  }
  return { coverage }
}
