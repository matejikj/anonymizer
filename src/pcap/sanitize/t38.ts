/**
 * T37 — T.38 / UDPTL baseline: preserve UDPTL seq/framing; mask IFP/page data (incl. FEC copies).
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { PatchCollector } from './PatchCollector'
import { sanitizeT38IfpPayload } from './t30/ifpWalk'
import type { AppLayerResult } from './types'

export function looksLikeUdptl(data: Uint8Array, offset: number, length: number): boolean {
  // UDPTL: seq number (2) + ASN.1 PER IFP — weak heuristic: length>=3, not RTP V=2
  if (length < 3) return false
  const v = (data[offset]! >> 6) & 0x03
  if (v === 2) return false // RTP
  return true
}

export function sanitizeT38Udptl(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeUdptl(buffer, offset, length)) return null
  // Preserve 2-byte sequence number; IFP walk maps T.30 TSI/CSI, masks page/FEC/unknown.
  let ifpIssues: string[] = ['t38-ifp-masked']
  if (length > 2) {
    const walk = sanitizeT38IfpPayload(
      buffer,
      offset + 2,
      length - 2,
      collector,
      mapping,
      intents,
      packetIndex,
    )
    ifpIssues = walk.issues
    intents?.recordMaskRange(packetIndex, offset + 2, length - 2, 't38-page-or-fec', 't38')
  }
  return {
    coverage: [
      { protocol: 't38', offset, length: Math.min(2, length), status: 'covered' },
      ...(length > 2
        ? [
            {
              protocol: 't38-ifp' as const,
              offset: offset + 2,
              length: length - 2,
              status: 'unsupported' as const,
            },
          ]
        : []),
    ],
    issues: ifpIssues,
  }
}
