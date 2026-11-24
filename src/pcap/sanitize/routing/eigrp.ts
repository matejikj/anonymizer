/**
 * T38 — EIGRP (IP proto 88). Header + TLV walk; auth TLV masked; router ID mapped.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import { mapRouterId, maskBytes, readU16 } from './common.ts'

export const IPPROTO_EIGRP = 88

const EIGRP_TLV_AUTH = 0x0002

export function sanitizeEigrp(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; lastCoveredOffset: number } {
  const coverage: LayerCoverage[] = []
  const len = data.length - offset
  if (len < 20) {
    coverage.push({ protocol: 'eigrp', offset, length: len, status: 'malformed' })
    return { coverage, lastCoveredOffset: offset }
  }
  // Ver(1) Opcode(1) Checksum(2) Flags(4) Seq(4) Ack(4) AS(4) — classic header 20 bytes
  mapRouterId(data, offset + 16, 'eigrp-as', collector, mapping, intents, packetIndex, 'eigrp')
  coverage.push({ protocol: 'eigrp', offset, length: 20, status: 'covered' })

  let pos = offset + 20
  const end = data.length
  while (pos + 4 <= end) {
    const tlvType = readU16(data, pos)
    const tlvLen = readU16(data, pos + 2)
    if (tlvLen < 4 || pos + tlvLen > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'eigrp-tlv-tail', 'eigrp')
      coverage.push({
        protocol: 'eigrp-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      return { coverage, lastCoveredOffset: end }
    }
    if (tlvType === EIGRP_TLV_AUTH) {
      maskBytes(collector, intents, packetIndex, pos + 4, tlvLen - 4, 'eigrp-auth', 'eigrp')
      coverage.push({
        protocol: 'eigrp-auth',
        offset: pos,
        length: tlvLen,
        status: 'redacted',
      })
    } else {
      // Routes / parameters: mask value (prefix dictionary incomplete) — type/len preserved.
      if (tlvLen > 4) {
        maskBytes(collector, intents, packetIndex, pos + 4, tlvLen - 4, 'eigrp-tlv', 'eigrp')
      }
      coverage.push({
        protocol: 'eigrp-tlv',
        offset: pos,
        length: tlvLen,
        status: 'redacted',
      })
    }
    pos += tlvLen
  }
  return { coverage, lastCoveredOffset: pos }
}
