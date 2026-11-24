/**
 * T38 — BGP-4 (TCP 179). OPEN identifier + ASN; UPDATE NEXT_HOP; unknown attrs masked.
 * RFC 4271. Marker+length framing.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { mapAsnAt, mapIpv4At, mapRouterId, maskBytes, readU16 } from './common.ts'

export const BGP_TCP_PORT = 179

const BGP_OPEN = 1
const BGP_UPDATE = 2
const BGP_NOTIFICATION = 3
const BGP_KEEPALIVE = 4

export function sanitizeBgp(
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
  if (srcPort !== BGP_TCP_PORT && dstPort !== BGP_TCP_PORT) return null
  if (length < 19) {
    return { coverage: [{ protocol: 'bgp', offset, length, status: 'malformed' }] }
  }

  const coverage: AppLayerResult['coverage'] = []
  let pos = offset
  const end = offset + length

  while (pos + 19 <= end) {
    // Marker 16 × 0xff
    let markerOk = true
    for (let i = 0; i < 16; i++) {
      if (buffer[pos + i] !== 0xff) {
        markerOk = false
        break
      }
    }
    if (!markerOk) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'bgp-desync', 'bgp')
      coverage.push({
        protocol: 'bgp-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      break
    }
    const msgLen = readU16(buffer, pos + 16)
    const type = buffer[pos + 18]!
    if (msgLen < 19 || pos + msgLen > end) {
      coverage.push({ protocol: 'bgp', offset: pos, length: end - pos, status: 'malformed' })
      break
    }

    coverage.push({ protocol: 'bgp', offset: pos, length: 19, status: 'covered' })
    const bodyOff = pos + 19
    const bodyLen = msgLen - 19

    if (type === BGP_OPEN && bodyLen >= 10) {
      // Version(1) MyAS(2) Hold(2) BGP ID(4) OptLen(1) …
      mapAsnAt(buffer, bodyOff + 1, 2, collector, mapping, intents, packetIndex, 'bgp')
      mapRouterId(buffer, bodyOff + 5, 'bgp', collector, mapping, intents, packetIndex, 'bgp')
      coverage.push({ protocol: 'bgp-open', offset: bodyOff, length: bodyLen, status: 'covered' })
      if (bodyLen > 10) {
        maskBytes(collector, intents, packetIndex, bodyOff + 10, bodyLen - 10, 'bgp-open-opt', 'bgp')
        coverage.push({
          protocol: 'bgp-open-opt',
          offset: bodyOff + 10,
          length: bodyLen - 10,
          status: 'redacted',
        })
      }
    } else if (type === BGP_UPDATE && bodyLen >= 4) {
      // Withdrawn len + attrs + NLRI — map NEXT_HOP (type 3) when found; else mask bodies
      sanitizeBgpUpdate(buffer, bodyOff, bodyLen, collector, mapping, packetIndex, intents, coverage)
    } else if (type === BGP_NOTIFICATION && bodyLen > 2) {
      // Error code/subcode preserve; data may echo original — mask
      coverage.push({ protocol: 'bgp-notification', offset: bodyOff, length: 2, status: 'covered' })
      if (bodyLen > 2) {
        maskBytes(collector, intents, packetIndex, bodyOff + 2, bodyLen - 2, 'bgp-notify-data', 'bgp')
        coverage.push({
          protocol: 'bgp-notification-data',
          offset: bodyOff + 2,
          length: bodyLen - 2,
          status: 'redacted',
        })
      }
    } else if (type === BGP_KEEPALIVE) {
      // header only
    } else if (bodyLen > 0) {
      maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, 'bgp-body', 'bgp')
      coverage.push({ protocol: 'bgp-body', offset: bodyOff, length: bodyLen, status: 'redacted' })
    }

    pos += msgLen
  }

  return { coverage }
}

function sanitizeBgpUpdate(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: AppLayerResult['coverage'],
): void {
  if (length < 4) {
    maskBytes(collector, intents, packetIndex, offset, length, 'bgp-update', 'bgp')
    coverage.push({ protocol: 'bgp-update', offset, length, status: 'redacted' })
    return
  }
  const withdrawnLen = readU16(buffer, offset)
  let pos = offset + 2
  if (withdrawnLen > 0 && pos + withdrawnLen <= offset + length) {
    maskBytes(collector, intents, packetIndex, pos, withdrawnLen, 'bgp-withdrawn', 'bgp')
    coverage.push({
      protocol: 'bgp-withdrawn',
      offset: pos,
      length: withdrawnLen,
      status: 'redacted',
    })
    pos += withdrawnLen
  }
  if (pos + 2 > offset + length) return
  const attrLen = readU16(buffer, pos)
  pos += 2
  const attrEnd = Math.min(offset + length, pos + attrLen)
  let ap = pos
  while (ap + 3 <= attrEnd) {
    const flags = buffer[ap]!
    const typeCode = buffer[ap + 1]!
    const extended = (flags & 0x10) !== 0
    let alen: number
    let hdr = 3
    if (extended) {
      if (ap + 4 > attrEnd) break
      alen = readU16(buffer, ap + 2)
      hdr = 4
    } else {
      alen = buffer[ap + 2]!
    }
    if (ap + hdr + alen > attrEnd) break
    const valOff = ap + hdr
    if (typeCode === 3 && alen === 4) {
      // NEXT_HOP
      mapIpv4At(buffer, valOff, collector, mapping, intents, packetIndex, 'bgp')
      coverage.push({ protocol: 'bgp-next-hop', offset: valOff, length: 4, status: 'covered' })
    } else if (typeCode === 2 && alen >= 2) {
      // AS_PATH — map AS numbers, preserve segment structure
      let sp = valOff
      const send = valOff + alen
      while (sp + 2 <= send) {
        const segLen = buffer[sp + 1]!
        sp += 2
        for (let i = 0; i < segLen && sp + 2 <= send; i++) {
          // AS2 baseline; AS4 would be 4 — detect by remaining length divisible by 4 when seg suggests
          if (sp + 4 <= send && (send - sp) % 4 === 0 && segLen * 4 === send - (sp - i * 4 - 2 + 2)) {
            // ambiguous — use 2-byte classic
          }
          mapAsnAt(buffer, sp, 2, collector, mapping, intents, packetIndex, 'bgp')
          sp += 2
        }
      }
      coverage.push({ protocol: 'bgp-as-path', offset: valOff, length: alen, status: 'covered' })
    } else {
      maskBytes(collector, intents, packetIndex, valOff, alen, `bgp-attr-${typeCode}`, 'bgp')
      coverage.push({
        protocol: 'bgp-attr',
        offset: ap,
        length: hdr + alen,
        status: 'redacted',
      })
    }
    ap += hdr + alen
  }
  pos = attrEnd
  if (pos < offset + length) {
    // NLRI
    maskBytes(collector, intents, packetIndex, pos, offset + length - pos, 'bgp-nlri', 'bgp')
    coverage.push({
      protocol: 'bgp-nlri',
      offset: pos,
      length: offset + length - pos,
      status: 'redacted',
    })
  }
}
