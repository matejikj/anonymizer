/**
 * Checksum recomputation engine — bottom-up after anonymization patches.
 */

import type { BytePatch } from '../sanitize/types'
import { locateLayers, type PacketLayers } from './locate'
import {
  computeChecksum,
  onesComplementSum,
  finalizeChecksum,
  writeChecksum,
  rfc1624Update,
} from './onesComplement'
import { sctpCrc32c, writeCrc32cLe, readCrc32cLe } from '../../crypto/crc32c'
import {
  type ChecksumDisposition,
  type ChecksumFieldResult,
  type ChecksumReport,
  type OriginalChecksumState,
  emptyChecksumCounts,
  emptyOriginalStateCounts,
  classifyOriginalChecksumState,
} from './types'
import { verifyChecksum } from './onesComplement'

export interface ChecksumContext {
  readonly linkType: number
  readonly capturedLen: number
  readonly originalLen: number
  readonly patches: readonly BytePatch[]
  /**
   * Pre-patch capture bytes (same length as `data` when possible).
   * Used only to classify originalState sidecard — never written.
   */
  readonly originalData?: Uint8Array
}

function pseudoHeaderSumIpv4(
  data: Uint8Array,
  srcOff: number,
  dstOff: number,
  proto: number,
  payloadLen: number,
): number {
  let sum = 0
  sum += (data[srcOff]! << 8) | data[srcOff + 1]!
  sum += (data[srcOff + 2]! << 8) | data[srcOff + 3]!
  sum += (data[dstOff]! << 8) | data[dstOff + 1]!
  sum += (data[dstOff + 2]! << 8) | data[dstOff + 3]!
  sum += proto
  sum += payloadLen
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
  return sum
}

function pseudoHeaderSumIpv6(
  data: Uint8Array,
  srcOff: number,
  dstOff: number,
  proto: number,
  payloadLen: number,
): number {
  let sum = onesComplementSum(data, srcOff, srcOff + 16)
  sum += onesComplementSum(data, dstOff, dstOff + 16)
  sum += (payloadLen >> 16) & 0xffff
  sum += payloadLen & 0xffff
  sum += 0
  sum += proto
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
  return sum
}

function classifyIpv4HeaderState(
  data: Uint8Array,
  ipStart: number,
  ipEnd: number,
  csumOff: number,
): OriginalChecksumState {
  const valid = verifyChecksum(data, ipStart, ipEnd, csumOff)
  return classifyOriginalChecksumState({
    present: true,
    truncated: false,
    verifiedValid: valid,
  })
}

function classifyIpv4TcpUdpState(input: {
  readonly data: Uint8Array
  readonly srcOff: number
  readonly dstOff: number
  readonly proto: number
  readonly l4Start: number
  readonly l4End: number
  readonly csumOff: number
  readonly inputCsum: number
  readonly truncated: boolean
}): OriginalChecksumState {
  if (input.truncated) {
    return 'NOT_VERIFIABLE_TRUNCATED'
  }
  if (input.proto === 17 && input.inputCsum === 0) {
    return 'NOT_PRESENT'
  }
  // Non-destructive: sum with checksum field treated as zero via onesComplement exclusion.
  let sum = pseudoHeaderSumIpv4(
    input.data,
    input.srcOff,
    input.dstOff,
    input.proto,
    input.l4End - input.l4Start,
  )
  // Sum L4 excluding checksum bytes (same as computeChecksum for contiguous fields).
  sum += onesComplementSum(input.data, input.l4Start, input.csumOff)
  sum += onesComplementSum(input.data, input.csumOff + 2, input.l4End)
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
  let expected = finalizeChecksum(sum)
  if (input.proto === 17 && expected === 0) expected = 0xffff

  if (expected === input.inputCsum) {
    return 'VALID'
  }
  if (input.inputCsum === 0 || input.inputCsum === 0xffff) {
    return 'OFFLOADED_PARTIAL'
  }
  return 'INVALID'
}

function dispositionForOriginal(
  state: OriginalChecksumState,
  rewriting: boolean,
): ChecksumDisposition {
  if (state === 'NOT_PRESENT') return 'preserved-zero'
  if (state === 'NOT_VERIFIABLE_TRUNCATED') return 'not-verifiable'
  if (state === 'OFFLOADED_PARTIAL' && !rewriting) return 'offload-suspected'
  if (state === 'INVALID' && !rewriting) return 'input-invalid'
  if (rewriting) return 'recomputed'
  return 'unchanged'
}

function patchTouchesRange(patches: readonly BytePatch[], start: number, end: number): boolean {
  for (const p of patches) {
    const pEnd = p.offset + p.data.length
    if (p.offset < end && pEnd > start) return true
  }
  return false
}

function record(
  fields: ChecksumFieldResult[],
  counts: Record<ChecksumDisposition, number>,
  originalStateCounts: Record<OriginalChecksumState, number>,
  layer: ChecksumFieldResult['layer'],
  offset: number,
  disposition: ChecksumDisposition,
  inputValue: number,
  outputValue: number,
  originalState: OriginalChecksumState,
): void {
  fields.push({ layer, offset, disposition, inputValue, outputValue, originalState })
  counts[disposition]++
  originalStateCounts[originalState]++
}

export function recomputeChecksums(data: Uint8Array, ctx: ChecksumContext): ChecksumReport {
  const fields: ChecksumFieldResult[] = []
  const counts = emptyChecksumCounts()
  const originalStateCounts = emptyOriginalStateCounts()
  const layers = locateLayers(data, ctx.linkType, ctx.capturedLen)

  if (layers.l3Proto === 'ipv4') {
    recomputeIpv4(data, layers, ctx, fields, counts, originalStateCounts)
  } else if (layers.l3Proto === 'ipv6') {
    recomputeIpv6Transport(data, layers, ctx, fields, counts, originalStateCounts)
  } else if (layers.l3Proto === 'none' && ctx.linkType === 1) {
    recomputeCdp(data, ctx, fields, counts, originalStateCounts)
  }

  return { fields, counts, originalStateCounts }
}

/**
 * CDP (SNAP OUI 00-00-0c, PID 0x2000) is a plain ones-complement checksum over the whole CDP
 * message, no pseudo-header — same shape as ICMP/VRRP, just carried directly over 802.3 LLC
 * instead of IP. `locateLayers` only recognizes IP/ARP EtherTypes, so this frame shape (an
 * 802.3 length field, not a normal EtherType) falls through to l3Proto 'none' and needs its
 * own detection here.
 */
function recomputeCdp(
  data: Uint8Array,
  ctx: ChecksumContext,
  fields: ChecksumFieldResult[],
  counts: Record<ChecksumDisposition, number>,
  originalStateCounts: Record<OriginalChecksumState, number>,
): void {
  if (ctx.capturedLen < 22) return
  let offset = 12
  let etherType = (data[offset]! << 8) | data[offset + 1]!
  while ((etherType === 0x8100 || etherType === 0x88a8) && offset + 4 <= ctx.capturedLen) {
    offset += 4
    etherType = (data[offset]! << 8) | data[offset + 1]!
  }
  if (etherType > 0x05dc) return // a real EtherType, not an 802.3 length field
  const llcOffset = offset + 2
  if (llcOffset + 8 > ctx.capturedLen) return
  if (data[llcOffset] !== 0xaa || data[llcOffset + 1] !== 0xaa) return // not SNAP
  const oui = (data[llcOffset + 3]! << 16) | (data[llcOffset + 4]! << 8) | data[llcOffset + 5]!
  const pid = (data[llcOffset + 6]! << 8) | data[llcOffset + 7]!
  if (oui !== 0x00000c || pid !== 0x2000) return // not CDP

  const cdpStart = llcOffset + 8
  if (cdpStart + 4 > ctx.capturedLen) return
  const csumOff = cdpStart + 2
  const inputCsum = (data[csumOff]! << 8) | data[csumOff + 1]!
  // Bounded by the 802.3 length field (LLC header + payload), never the raw captured/padded
  // frame length.
  const declaredLlcLen = etherType
  const cdpEnd = Math.min(llcOffset + declaredLlcLen, ctx.capturedLen)
  if (cdpEnd <= cdpStart) return

  if (!patchTouchesRange(ctx.patches, cdpStart, cdpEnd)) {
    record(fields, counts, originalStateCounts, 'cdp', csumOff, 'unchanged', inputCsum, inputCsum, classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }))
  } else {
    const newCsum = computeChecksum(data, cdpStart, cdpEnd, csumOff)
    writeChecksum(data, csumOff, newCsum)
    record(fields, counts, originalStateCounts, 'cdp', csumOff, 'recomputed', inputCsum, newCsum, classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }))
  }
}

function recomputeIpv4(
  data: Uint8Array,
  layers: PacketLayers,
  ctx: ChecksumContext,
  fields: ChecksumFieldResult[],
  counts: Record<ChecksumDisposition, number>,
  originalStateCounts: Record<OriginalChecksumState, number>,
): void {
  const ipStart = layers.l3Offset
  const ipEnd = layers.l3Offset + layers.ipv4HeaderLen
  const csumOff = ipStart + 10
  const inputCsum = (data[csumOff]! << 8) | data[csumOff + 1]!
  const classifySrc = ctx.originalData && ctx.originalData.length >= ipEnd ? ctx.originalData : data
  const ipv4Orig = classifyIpv4HeaderState(classifySrc, ipStart, ipEnd, csumOff)

  if (!patchTouchesRange(ctx.patches, ipStart, ipEnd)) {
    record(
      fields,
      counts,
      originalStateCounts,
      'ipv4',
      csumOff,
      dispositionForOriginal(ipv4Orig, false),
      inputCsum,
      inputCsum,
      ipv4Orig,
    )
  } else {
    // Recompute after address/header rewrite; sidecard keeps pre-sanitize state.
    const newCsum = computeChecksum(data, ipStart, ipEnd, csumOff)
    writeChecksum(data, csumOff, newCsum)
    record(
      fields,
      counts,
      originalStateCounts,
      'ipv4',
      csumOff,
      'recomputed',
      inputCsum,
      newCsum,
      ipv4Orig,
    )
  }

  if (layers.isFragment || layers.l4Proto === 'none') {
    if (layers.l4Proto !== 'none') {
      const l4CsumOff =
        layers.l4Proto === 'tcp' ? layers.l4Offset + 16
        : layers.l4Proto === 'udp' ? layers.l4Offset + 6
        : layers.l4Proto === 'sctp' ? layers.l4Offset + 8
        : layers.l4Proto === 'icmpv4' ? layers.l4Offset + 2
        : layers.l4Proto === 'vrrp' ? layers.l4Offset + 6
        : -1
      if (l4CsumOff >= 0) {
        const v =
          layers.l4Proto === 'sctp'
            ? readCrc32cLe(data, l4CsumOff)
            : (data[l4CsumOff]! << 8) | data[l4CsumOff + 1]!
        const layerName =
          layers.l4Proto === 'tcp' ? 'tcp'
          : layers.l4Proto === 'udp' ? 'udp'
          : layers.l4Proto === 'sctp' ? 'sctp'
          : layers.l4Proto === 'vrrp' ? 'vrrp'
          : 'icmpv4'
        record(fields, counts, originalStateCounts, layerName, l4CsumOff, 'not-verifiable', v, v, 'NOT_VERIFIABLE_TRUNCATED')
      }
    }
    return
  }

  // Bound every L4 checksum to the IPv4 datagram's own declared end, never to the raw
  // captured frame length — a short frame padded to the Ethernet minimum (60 bytes) has
  // trailer bytes past the datagram that must never enter a checksum sum. Distinguish an
  // already-truncated capture (declared end beyond what was captured — cannot safely
  // recompute) from a structurally invalid Total Length (smaller than the header itself).
  const declaredIpEnd = layers.l3Offset + layers.ipv4TotalLength
  const structurallyInvalidLength = layers.ipv4TotalLength < layers.ipv4HeaderLen
  const truncatedCapture = !structurallyInvalidLength && declaredIpEnd > ctx.capturedLen
  const boundaryTrustworthy = !structurallyInvalidLength && !truncatedCapture
  const ipPacketEnd = boundaryTrustworthy ? declaredIpEnd : ctx.capturedLen
  const payloadLen = ipPacketEnd - layers.l4Offset
  const srcOff = ipStart + 12
  const dstOff = ipStart + 16

  if (layers.l4Proto === 'tcp' && layers.l4Offset + 20 <= ctx.capturedLen) {
    const tcpStart = layers.l4Offset
    const csumOff = tcpStart + 16
    const inputCsum = (data[csumOff]! << 8) | data[csumOff + 1]!
    const tcpEnd = ipPacketEnd
    const classifySrc = ctx.originalData && ctx.originalData.length >= tcpEnd ? ctx.originalData : data
    const orig = classifyIpv4TcpUdpState({
      data: classifySrc,
      srcOff,
      dstOff,
      proto: 6,
      l4Start: tcpStart,
      l4End: tcpEnd,
      csumOff,
      inputCsum: (classifySrc[csumOff]! << 8) | classifySrc[csumOff + 1]!,
      truncated: !boundaryTrustworthy,
    })
    if (!boundaryTrustworthy) {
      record(fields, counts, originalStateCounts, 'tcp', csumOff, 'not-verifiable', inputCsum, inputCsum, orig)
    } else {
      const rewriting =
        patchTouchesRange(ctx.patches, tcpStart, tcpEnd)
        || patchTouchesRange(ctx.patches, srcOff, dstOff + 4)
      if (!rewriting) {
        record(
          fields,
          counts,
          originalStateCounts,
          'tcp',
          csumOff,
          dispositionForOriginal(orig, false),
          inputCsum,
          inputCsum,
          orig,
        )
      } else {
        writeChecksum(data, csumOff, 0)
        let sum = pseudoHeaderSumIpv4(data, srcOff, dstOff, 6, payloadLen)
        sum += onesComplementSum(data, tcpStart, tcpEnd)
        while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
        const newCsum = finalizeChecksum(sum)
        writeChecksum(data, csumOff, newCsum)
        record(fields, counts, originalStateCounts, 'tcp', csumOff, 'recomputed', inputCsum, newCsum, orig)
      }
    }
  } else if (layers.l4Proto === 'udp' && layers.l4Offset + 8 <= ctx.capturedLen) {
    const udpStart = layers.l4Offset
    const csumOff = udpStart + 6
    const inputCsum = (data[csumOff]! << 8) | data[csumOff + 1]!
    if (inputCsum === 0) {
      // RFC 768: 0x0000 means "checksum not used" — preserve that semantic.
      record(fields, counts, originalStateCounts, 'udp', csumOff, 'preserved-zero', 0, 0, 'NOT_PRESENT')
    } else if (!boundaryTrustworthy) {
      record(
        fields,
        counts,
        originalStateCounts,
        'udp',
        csumOff,
        'not-verifiable',
        inputCsum,
        inputCsum,
        'NOT_VERIFIABLE_TRUNCATED',
      )
    } else {
      const declaredUdpLength = (data[udpStart + 4]! << 8) | data[udpStart + 5]!
      const udpEnd = Math.min(udpStart + declaredUdpLength, ipPacketEnd, ctx.capturedLen)
      if (declaredUdpLength < 8 || udpEnd < udpStart + 8) {
        record(
          fields,
          counts,
          originalStateCounts,
          'udp',
          csumOff,
          'not-verifiable',
          inputCsum,
          inputCsum,
          'NOT_VERIFIABLE_TRUNCATED',
        )
      } else {
        const orig = classifyIpv4TcpUdpState({
          data: ctx.originalData && ctx.originalData.length >= udpEnd ? ctx.originalData : data,
          srcOff,
          dstOff,
          proto: 17,
          l4Start: udpStart,
          l4End: udpEnd,
          csumOff,
          inputCsum,
          truncated: false,
        })
        const rewriting =
          patchTouchesRange(ctx.patches, udpStart, udpEnd)
          || patchTouchesRange(ctx.patches, srcOff, dstOff + 4)
        if (!rewriting) {
          record(
            fields,
            counts,
            originalStateCounts,
            'udp',
            csumOff,
            dispositionForOriginal(orig, false),
            inputCsum,
            inputCsum,
            orig,
          )
        } else {
          writeChecksum(data, csumOff, 0)
          let sum = pseudoHeaderSumIpv4(data, srcOff, dstOff, 17, udpEnd - udpStart)
          sum += onesComplementSum(data, udpStart, udpEnd)
          while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
          let newCsum = finalizeChecksum(sum)
          if (newCsum === 0) newCsum = 0xffff
          writeChecksum(data, csumOff, newCsum)
          record(fields, counts, originalStateCounts, 'udp', csumOff, 'recomputed', inputCsum, newCsum, orig)
        }
      }
    }
  } else if (layers.l4Proto === 'icmpv4' && layers.l4Offset + 8 <= ctx.capturedLen) {
    const icmpStart = layers.l4Offset
    const csumOff = icmpStart + 2
    const inputCsum = (data[csumOff]! << 8) | data[csumOff + 1]!
    if (!boundaryTrustworthy) {
      record(fields, counts, originalStateCounts, 'icmpv4', csumOff, 'not-verifiable', inputCsum, inputCsum, 'NOT_VERIFIABLE_TRUNCATED')
    } else {
      const icmpEnd = ipPacketEnd
      if (!patchTouchesRange(ctx.patches, icmpStart, icmpEnd)) {
        record(fields, counts, originalStateCounts, 'icmpv4', csumOff, 'unchanged', inputCsum, inputCsum, classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }))
      } else {
        // ICMP error embedded IPv4 header
        const icmpType = data[icmpStart]!
        if (icmpType === 3 || icmpType === 4 || icmpType === 5 || icmpType === 11 || icmpType === 12) {
          const embOff = icmpStart + 8
          if (embOff + 20 <= icmpEnd && (data[embOff]! >> 4) === 4) {
            const embCsumOff = embOff + 10
            const embInput = (data[embCsumOff]! << 8) | data[embCsumOff + 1]!
            const embHeaderEnd = embOff + (data[embOff]! & 0x0f) * 4
            if (embHeaderEnd >= embOff + 20 && embHeaderEnd <= icmpEnd
              && patchTouchesRange(ctx.patches, embOff, embHeaderEnd)) {
              const embNew = computeChecksum(data, embOff, embHeaderEnd, embCsumOff)
              writeChecksum(data, embCsumOff, embNew)
              record(fields, counts, originalStateCounts, 'icmp-embedded-ipv4', embCsumOff, 'recomputed', embInput, embNew, classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }))
            }
          }
        }
        // Enclosing checksum includes the finalized quoted header.
        const newCsum = computeChecksum(data, icmpStart, icmpEnd, csumOff)
        writeChecksum(data, csumOff, newCsum)
        record(fields, counts, originalStateCounts, 'icmpv4', csumOff, 'recomputed', inputCsum, newCsum, classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }))
      }
    }
  } else if (layers.l4Proto === 'vrrp' && layers.l4Offset + 8 <= ctx.capturedLen) {
    // RFC 3768/5798: plain ones-complement over the whole VRRP message, no pseudo-header —
    // same shape as ICMP. The embedded virtual IP(s) this sanitizer remaps live inside this
    // same span, so any anonymized VRRP packet needs its checksum recomputed here too.
    const vrrpStart = layers.l4Offset
    const csumOff = vrrpStart + 6
    const inputCsum = (data[csumOff]! << 8) | data[csumOff + 1]!
    if (!boundaryTrustworthy) {
      record(fields, counts, originalStateCounts, 'vrrp', csumOff, 'not-verifiable', inputCsum, inputCsum, 'NOT_VERIFIABLE_TRUNCATED')
    } else {
      const vrrpEnd = ipPacketEnd
      if (!patchTouchesRange(ctx.patches, vrrpStart, vrrpEnd)) {
        record(fields, counts, originalStateCounts, 'vrrp', csumOff, 'unchanged', inputCsum, inputCsum, classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }))
      } else {
        const newCsum = computeChecksum(data, vrrpStart, vrrpEnd, csumOff)
        writeChecksum(data, csumOff, newCsum)
        record(fields, counts, originalStateCounts, 'vrrp', csumOff, 'recomputed', inputCsum, newCsum, classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }))
      }
    }
  } else if (layers.l4Proto === 'sctp' && layers.l4Offset + 12 <= ctx.capturedLen) {
    recomputeSctpCrc(data, layers.l4Offset, ipPacketEnd, ctx, fields, counts, originalStateCounts, !boundaryTrustworthy)
  }
}

function recomputeSctpCrc(
  data: Uint8Array,
  sctpStart: number,
  packetEnd: number,
  ctx: ChecksumContext,
  fields: ChecksumFieldResult[],
  counts: Record<ChecksumDisposition, number>,
  originalStateCounts: Record<OriginalChecksumState, number>,
  truncated: boolean,
): void {
  const csumOff = sctpStart + 8
  const inputCsum = readCrc32cLe(data, csumOff)
  if (truncated || packetEnd < sctpStart + 12) {
    record(fields, counts, originalStateCounts, 'sctp', csumOff, 'not-verifiable', inputCsum, inputCsum, 'NOT_VERIFIABLE_TRUNCATED')
    return
  }
  const sctpLen = packetEnd - sctpStart
  const rewriting = patchTouchesRange(ctx.patches, sctpStart, packetEnd)
  if (!rewriting) {
    record(
      fields,
      counts,
      originalStateCounts,
      'sctp',
      csumOff,
      'unchanged',
      inputCsum,
      inputCsum,
      classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }),
    )
    return
  }
  const newCsum = sctpCrc32c(data, sctpStart, sctpLen)
  writeCrc32cLe(data, csumOff, newCsum)
  record(
    fields,
    counts,
    originalStateCounts,
    'sctp',
    csumOff,
    'recomputed',
    inputCsum,
    newCsum,
    classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }),
  )
}

function recomputeIpv6Transport(
  data: Uint8Array,
  layers: PacketLayers,
  ctx: ChecksumContext,
  fields: ChecksumFieldResult[],
  counts: Record<ChecksumDisposition, number>,
  originalStateCounts: Record<OriginalChecksumState, number>,
): void {
  if (layers.isFragment || layers.l4Proto === 'none') return

  // Same padding-vs-declared-length distinction as IPv4 (see recomputeIpv4): bound every
  // checksum to the datagram's own declared end, never to the raw captured frame length.
  const declaredIpv6End = layers.l3Offset + 40 + layers.ipv6PayloadLength
  const truncatedCapture = declaredIpv6End > ctx.capturedLen
  const ipPacketEnd = truncatedCapture ? ctx.capturedLen : declaredIpv6End
  const payloadLen = ipPacketEnd - layers.l4Offset
  const srcOff = layers.l3Offset + 8
  const dstOff = layers.l3Offset + 24

  if (layers.l4Proto === 'tcp' && layers.l4Offset + 20 <= ctx.capturedLen) {
    const tcpStart = layers.l4Offset
    const csumOff = tcpStart + 16
    const inputCsum = (data[csumOff]! << 8) | data[csumOff + 1]!
    if (truncatedCapture) {
      record(fields, counts, originalStateCounts, 'tcp', csumOff, 'not-verifiable', inputCsum, inputCsum, 'NOT_VERIFIABLE_TRUNCATED')
    } else {
      const tcpEnd = ipPacketEnd
      writeChecksum(data, csumOff, 0)
      let sum = pseudoHeaderSumIpv6(data, srcOff, dstOff, 6, payloadLen)
      sum += onesComplementSum(data, tcpStart, tcpEnd)
      while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
      const newCsum = finalizeChecksum(sum)
      writeChecksum(data, csumOff, newCsum)
      const disp: ChecksumDisposition = patchTouchesRange(ctx.patches, tcpStart, tcpEnd) || patchTouchesRange(ctx.patches, srcOff, dstOff + 16)
        ? 'recomputed' : 'unchanged'
      record(fields, counts, originalStateCounts, 'tcp', csumOff, disp === 'unchanged' ? 'unchanged' : 'recomputed', inputCsum, newCsum, classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }))
    }
  } else if (layers.l4Proto === 'udp' && layers.l4Offset + 8 <= ctx.capturedLen) {
    const udpStart = layers.l4Offset
    const csumOff = udpStart + 6
    const inputCsum = (data[csumOff]! << 8) | data[csumOff + 1]!
    if (truncatedCapture) {
      record(fields, counts, originalStateCounts, 'udp', csumOff, 'not-verifiable', inputCsum, inputCsum, 'NOT_VERIFIABLE_TRUNCATED')
    } else {
      // Fail-closed (RFC 8200): unlike IPv4, a zero UDP checksum is never valid over IPv6 —
      // always compute and write a real one rather than leaving the invalid 0x0000 in place.
      const udpEnd = Math.min(udpStart + ((data[udpStart + 4]! << 8) | data[udpStart + 5]!), ipPacketEnd, ctx.capturedLen)
      if (udpEnd < udpStart + 8) {
        record(fields, counts, originalStateCounts, 'udp', csumOff, 'not-verifiable', inputCsum, inputCsum, 'NOT_VERIFIABLE_TRUNCATED')
      } else {
        writeChecksum(data, csumOff, 0)
        let sum = pseudoHeaderSumIpv6(data, srcOff, dstOff, 17, udpEnd - udpStart)
        sum += onesComplementSum(data, udpStart, udpEnd)
        while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
        let newCsum = finalizeChecksum(sum)
        if (newCsum === 0) newCsum = 0xffff
        writeChecksum(data, csumOff, newCsum)
        record(fields, counts, originalStateCounts, 'udp', csumOff, 'recomputed', inputCsum, newCsum, classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }))
      }
    }
  } else if (layers.l4Proto === 'sctp' && layers.l4Offset + 12 <= ctx.capturedLen) {
    recomputeSctpCrc(data, layers.l4Offset, ipPacketEnd, ctx, fields, counts, originalStateCounts, truncatedCapture)
  } else if (layers.l4Proto === 'icmpv6' && layers.l4Offset + 8 <= ctx.capturedLen) {
    const icmpStart = layers.l4Offset
    const csumOff = icmpStart + 2
    const inputCsum = (data[csumOff]! << 8) | data[csumOff + 1]!
    if (truncatedCapture) {
      record(fields, counts, originalStateCounts, 'icmpv6', csumOff, 'not-verifiable', inputCsum, inputCsum, 'NOT_VERIFIABLE_TRUNCATED')
    } else {
      const icmpEnd = ipPacketEnd
      writeChecksum(data, csumOff, 0)
      let sum = pseudoHeaderSumIpv6(data, srcOff, dstOff, 58, payloadLen)
      sum += onesComplementSum(data, icmpStart, icmpEnd)
      while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
      const newCsum = finalizeChecksum(sum)
      writeChecksum(data, csumOff, newCsum)
      record(fields, counts, originalStateCounts, 'icmpv6', csumOff, 'recomputed', inputCsum, newCsum, classifyOriginalChecksumState({ present: true, truncated: false, verifiedValid: null }))
    }
  }
}

/** Incremental update when only IP addresses changed and full L4 is captured. */
export function tryIncrementalIpUpdate(
  original: Uint8Array,
  patched: Uint8Array,
  layers: PacketLayers,
  oldSrc: Uint8Array,
  newSrc: Uint8Array,
  oldDst: Uint8Array,
  newDst: Uint8Array,
): boolean {
  if (layers.l3Proto !== 'ipv4' || layers.isFragment) return false
  const csumOff =
    layers.l4Proto === 'tcp' ? layers.l4Offset + 16
    : layers.l4Proto === 'udp' ? layers.l4Offset + 6
    : -1
  if (csumOff < 0) return false
  const oldCsum = (original[csumOff]! << 8) | original[csumOff + 1]!
  if (oldCsum === 0 && layers.l4Proto === 'udp') return true
  let csum = oldCsum
  for (let i = 0; i < 4; i += 2) {
    const ow = (oldSrc[i]! << 8) | oldSrc[i + 1]!
    const nw = (newSrc[i]! << 8) | newSrc[i + 1]!
    csum = rfc1624Update(csum, ow, nw)
    const ow2 = (oldDst[i]! << 8) | oldDst[i + 1]!
    const nw2 = (newDst[i]! << 8) | newDst[i + 1]!
    csum = rfc1624Update(csum, ow2, nw2)
  }
  writeChecksum(patched, csumOff, csum)
  return true
}
