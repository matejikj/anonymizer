/**
 * IPv6 extension-header sanitizer (enterprise step 9).
 * SRH Type 4 segment lists, Destination/Hop-by-Hop Home Address, opaque options.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { LayerCoverage } from './types'
import type { PatchCollector } from './PatchCollector'
import { ipv6Bytes16ToText, ipv6TextToBytes16 } from './ipv6Wire'
import { createMaskFill } from './maskFill'

/** IPv6 next-header values. */
export const IPV6_NH = {
  HOP_BY_HOP: 0,
  ROUTING: 43,
  FRAGMENT: 44,
  DEST_OPTS: 60,
  AH: 51,
  ICMPV6: 58,
} as const

/** Destination/Hop-by-Hop option types. */
const OPT_PAD1 = 0
const OPT_PADN = 1
const OPT_HOME_ADDRESS = 201 // 0xC9 — MIPv6 Home Address (RFC 6275)

/** Routing header type 4 = Segment Routing (RFC 8754). */
const ROUTING_TYPE_SRH = 4

export interface SanitizeIpv6ExtensionsInput {
  readonly buffer: Uint8Array
  /** Offset of first byte after fixed IPv6 header (byte 40 of IPv6). */
  readonly startOffset: number
  readonly initialNextHeader: number
  readonly collector: PatchCollector
  readonly mapping: MappingLike
  readonly packetIndex: number
  readonly intents?: IntentCollector
  readonly maxDepth?: number
}

export interface SanitizeIpv6ExtensionsResult {
  readonly nextHeader: number
  readonly payloadOffset: number
  readonly isFragment: boolean
  readonly coverage: LayerCoverage[]
  readonly lastCoveredOffset: number
}

/**
 * Walk IPv6 extension headers, mapping addresses in SRH / Home Address options.
 */
export function sanitizeIpv6Extensions(
  input: SanitizeIpv6ExtensionsInput,
): SanitizeIpv6ExtensionsResult {
  const {
    buffer,
    startOffset,
    initialNextHeader,
    collector,
    mapping,
    packetIndex,
    intents,
  } = input
  const maxDepth = input.maxDepth ?? 10
  const coverage: LayerCoverage[] = []

  let nextHeader = initialNextHeader
  let hdrOffset = startOffset
  let lastCovered = startOffset
  let isFragment = false
  let depth = 0

  while (depth < maxDepth) {
    if (nextHeader === IPV6_NH.HOP_BY_HOP || nextHeader === IPV6_NH.DEST_OPTS) {
      if (hdrOffset + 2 > buffer.length) break
      const extLen = (buffer[hdrOffset + 1]! + 1) * 8
      if (hdrOffset + extLen > buffer.length) {
        coverage.push({
          protocol: nextHeader === IPV6_NH.HOP_BY_HOP ? 'ipv6-hbh' : 'ipv6-dstopt',
          offset: hdrOffset,
          length: buffer.length - hdrOffset,
          status: 'malformed',
        })
        break
      }
      const nh = buffer[hdrOffset]!
      sanitizeHbhOrDstOpts(
        buffer,
        hdrOffset,
        extLen,
        nextHeader === IPV6_NH.HOP_BY_HOP ? 'ipv6-hbh' : 'ipv6-dstopt',
        collector,
        mapping,
        packetIndex,
        intents,
        coverage,
      )
      nextHeader = nh
      hdrOffset += extLen
      lastCovered = hdrOffset
      depth++
      continue
    }

    if (nextHeader === IPV6_NH.ROUTING) {
      if (hdrOffset + 4 > buffer.length) break
      const extLen = (buffer[hdrOffset + 1]! + 1) * 8
      if (hdrOffset + extLen > buffer.length) {
        coverage.push({
          protocol: 'ipv6-srh',
          offset: hdrOffset,
          length: buffer.length - hdrOffset,
          status: 'malformed',
        })
        break
      }
      const nh = buffer[hdrOffset]!
      const routingType = buffer[hdrOffset + 2]!
      if (routingType === ROUTING_TYPE_SRH) {
        sanitizeSrh(buffer, hdrOffset, extLen, collector, mapping, packetIndex, intents, coverage)
      } else {
        // Other routing types — keep header structure, mask address-bearing body.
        if (extLen > 8) {
          const fill = createMaskFill({
            length: extLen - 8,
            packetIndex,
            offset: hdrOffset + 8,
            domain: `ipv6-routing-type-${routingType}`,
          })
          collector.maskRange(hdrOffset + 8, fill)
          intents?.recordMaskRange(
            packetIndex,
            hdrOffset + 8,
            extLen - 8,
            `ipv6-routing-${routingType}`,
            'ipv6',
          )
        }
        coverage.push({
          protocol: `ipv6-routing-${routingType}`,
          offset: hdrOffset,
          length: extLen,
          status: 'redacted',
        })
      }
      nextHeader = nh
      hdrOffset += extLen
      lastCovered = hdrOffset
      depth++
      continue
    }

    if (nextHeader === IPV6_NH.FRAGMENT) {
      if (hdrOffset + 8 > buffer.length) break
      const nh = buffer[hdrOffset]!
      const fOffset = ((buffer[hdrOffset + 2]! << 8) | buffer[hdrOffset + 3]!) >> 3
      if (fOffset > 0) isFragment = true
      coverage.push({ protocol: 'ipv6-fragment', offset: hdrOffset, length: 8, status: 'covered' })
      nextHeader = nh
      hdrOffset += 8
      lastCovered = hdrOffset
      depth++
      continue
    }

    if (nextHeader === IPV6_NH.AH) {
      if (hdrOffset + 2 > buffer.length) break
      const ahLen = (buffer[hdrOffset + 1]! + 2) * 4
      if (hdrOffset + ahLen > buffer.length) break
      const nh = buffer[hdrOffset]!
      coverage.push({ protocol: 'ipv6-ah', offset: hdrOffset, length: ahLen, status: 'covered' })
      nextHeader = nh
      hdrOffset += ahLen
      lastCovered = hdrOffset
      depth++
      continue
    }

    break
  }

  return {
    nextHeader,
    payloadOffset: hdrOffset,
    isFragment,
    coverage,
    lastCoveredOffset: lastCovered,
  }
}

function sanitizeSrh(
  buffer: Uint8Array,
  offset: number,
  extLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
): void {
  // SRH fixed: Next Header(1) Hdr Ext Len(1) Routing Type(1) Segments Left(1)
  //            Last Entry(1) Flags(1) Tag(2) + Segment List[0..Last Entry]
  if (extLen < 8) {
    coverage.push({ protocol: 'ipv6-srh', offset, length: extLen, status: 'malformed' })
    return
  }
  const lastEntry = buffer[offset + 4]!
  const segments = lastEntry + 1
  let segOff = offset + 8
  let mapped = 0
  for (let i = 0; i < segments; i++) {
    if (segOff + 16 > offset + extLen) break
    patchIpv6Field(buffer, segOff, collector, mapping, packetIndex, intents)
    segOff += 16
    mapped++
  }
  // TLVs after segment list — mask remaining (may contain HMAC etc.)
  if (segOff < offset + extLen) {
    const rem = offset + extLen - segOff
    const fill = createMaskFill({
      length: rem,
      packetIndex,
      offset: segOff,
      domain: 'ipv6-srh-tlv',
    })
    collector.maskRange(segOff, fill)
    intents?.recordMaskRange(packetIndex, segOff, rem, 'ipv6-srh-tlv', 'ipv6')
  }
  coverage.push({
    protocol: 'ipv6-srh',
    offset,
    length: extLen,
    status: mapped > 0 ? 'covered' : 'redacted',
  })
}

function sanitizeHbhOrDstOpts(
  buffer: Uint8Array,
  offset: number,
  extLen: number,
  protocol: string,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
): void {
  // Skip Next Header + Hdr Ext Len
  let pos = offset + 2
  const end = offset + extLen
  let sawHome = false
  while (pos < end) {
    const optType = buffer[pos]!
    if (optType === OPT_PAD1) {
      pos++
      continue
    }
    if (pos + 2 > end) break
    const optLen = buffer[pos + 1]!
    const optEnd = pos + 2 + optLen
    if (optEnd > end) {
      coverage.push({ protocol, offset: pos, length: end - pos, status: 'malformed' })
      return
    }
    if (optType === OPT_HOME_ADDRESS && optLen === 16) {
      patchIpv6Field(buffer, pos + 2, collector, mapping, packetIndex, intents)
      coverage.push({
        protocol: 'ipv6-home-address',
        offset: pos,
        length: 2 + optLen,
        status: 'covered',
      })
      sawHome = true
    } else if (optType === OPT_PADN) {
      // padding — leave
    } else if (optLen > 0) {
      // Unknown option data — mask (may carry identifiers)
      const fill = createMaskFill({
        length: optLen,
        packetIndex,
        offset: pos + 2,
        domain: `ipv6-opt-${optType}`,
      })
      collector.maskRange(pos + 2, fill)
      intents?.recordMaskRange(packetIndex, pos + 2, optLen, `ipv6-opt-${optType}`, 'ipv6')
      coverage.push({
        protocol: `ipv6-opt-${optType}`,
        offset: pos,
        length: 2 + optLen,
        status: 'redacted',
      })
    }
    pos = optEnd
  }
  coverage.push({
    protocol,
    offset,
    length: extLen,
    status: sawHome ? 'covered' : 'covered',
  })
}

function patchIpv6Field(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const ip = ipv6Bytes16ToText(buffer, offset)
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv6', ip, 16)
  try {
    collector.addDeferred(offset, 16, ({ mapping: live }) => {
      const mapped = live.map('ipv6', ip)
      return ipv6TextToBytes16(mapped)
    })
  } catch {
    /* overlap */
  }
}
