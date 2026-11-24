/**
 * T38 — LDP (TCP/UDP 646). LSR ID mapped; auth/MD5-related TLVs masked.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { mapRouterId, maskBytes, readU16 } from './common.ts'

export const LDP_PORT = 646

export function sanitizeLdp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (srcPort !== LDP_PORT && dstPort !== LDP_PORT) return null
  if (length < 10) {
    return { coverage: [{ protocol: 'ldp', offset, length, status: 'malformed' }] }
  }
  const coverage: AppLayerResult['coverage'] = []
  // Version(2) PDU Length(2) LSR ID(4) Label space(2)
  mapRouterId(buffer, offset + 4, 'ldp', collector, mapping, intents, packetIndex, 'ldp')
  coverage.push({ protocol: 'ldp', offset, length: 10, status: 'covered' })

  let pos = offset + 10
  const end = offset + length
  while (pos + 4 <= end) {
    const u = readU16(buffer, pos)
    const msgType = u & 0x7fff
    const msgLen = readU16(buffer, pos + 2)
    if (msgLen < 4 || pos + 4 + msgLen > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'ldp-tail', 'ldp')
      coverage.push({
        protocol: 'ldp-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      break
    }
    // Message ID (4) + TLVs
    const tlvStart = pos + 8
    const tlvEnd = pos + 4 + msgLen
    let tp = tlvStart
    while (tp + 4 <= tlvEnd) {
      const tlvU = readU16(buffer, tp)
      const tlvType = tlvU & 0x3fff
      const tlvLen = readU16(buffer, tp + 2)
      if (tp + 4 + tlvLen > tlvEnd) break
      // Cryptographic auth / MD5 (vendor / RFC 5036 auth TLV family) — mask values
      if (tlvType === 0x0401 || tlvType === 0x0402 || tlvType === 0x0403) {
        maskBytes(collector, intents, packetIndex, tp + 4, tlvLen, 'ldp-auth', 'ldp')
        coverage.push({
          protocol: 'ldp-auth',
          offset: tp,
          length: 4 + tlvLen,
          status: 'redacted',
        })
      } else if (tlvLen > 0) {
        maskBytes(collector, intents, packetIndex, tp + 4, tlvLen, 'ldp-tlv', 'ldp')
        coverage.push({
          protocol: 'ldp-tlv',
          offset: tp,
          length: 4 + tlvLen,
          status: 'redacted',
        })
      }
      tp += 4 + tlvLen
    }
    void msgType
    pos = tlvEnd
  }
  return { coverage }
}
