/**
 * T38 — BFD control (UDP 3784/4784). Discriminators preserved; auth section masked.
 * RFC 5880.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { maskBytes } from './common.ts'

export const BFD_UDP_PORTS = new Set([3784, 4784])

export function sanitizeBfd(
  buffer: Uint8Array,
  offset: number,
  length: number,
  dstPort: number,
  collector: PatchCollector,
  packetIndex: number,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!BFD_UDP_PORTS.has(dstPort)) return null
  if (length < 24) {
    return { coverage: [{ protocol: 'bfd', offset, length, status: 'malformed' }] }
  }
  const coverage: AppLayerResult['coverage'] = []
  // Vers|Diag, Sta|Flags, Detect Mult, Length
  const flags = buffer[offset + 1]!
  const authPresent = (flags & 0x02) !== 0
  const bfdLen = buffer[offset + 3]!
  const headerLen = Math.min(length, bfdLen >= 24 ? bfdLen : 24)
  coverage.push({ protocol: 'bfd', offset, length: Math.min(24, length), status: 'covered' })

  if (authPresent && headerLen > 24) {
    maskBytes(collector, intents, packetIndex, offset + 24, headerLen - 24, 'bfd-auth', 'bfd')
    coverage.push({
      protocol: 'bfd-auth',
      offset: offset + 24,
      length: headerLen - 24,
      status: 'redacted',
    })
  } else if (length > 24) {
    // Optional auth without flag or trailing — mask rest
    maskBytes(collector, intents, packetIndex, offset + 24, length - 24, 'bfd-tail', 'bfd')
    coverage.push({
      protocol: 'bfd-body',
      offset: offset + 24,
      length: length - 24,
      status: 'redacted',
    })
  }
  return { coverage }
}
