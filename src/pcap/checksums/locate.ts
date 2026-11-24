/**
 * Locate checksum-relevant layers in a captured packet buffer.
 */

export interface PacketLayers {
  readonly linkType: number
  readonly l2Offset: number
  readonly l3Offset: number
  readonly l3Proto: 'ipv4' | 'ipv6' | 'arp' | 'none'
  readonly l4Offset: number
  readonly l4Proto: 'tcp' | 'udp' | 'sctp' | 'icmpv4' | 'icmpv6' | 'vrrp' | 'none'
  readonly ipv4HeaderLen: number
  /** IPv4 Total Length field (whole datagram: header + payload), when l3Proto is 'ipv4'. */
  readonly ipv4TotalLength: number
  /** IPv6 Payload Length field (everything after the fixed 40-byte header), when l3Proto is 'ipv6'. */
  readonly ipv6PayloadLength: number
  readonly isFragment: boolean
  readonly capturedLen: number
}

export function locateLayers(data: Uint8Array, linkType: number, capturedLen: number): PacketLayers {
  const none: PacketLayers = {
    linkType,
    l2Offset: 0,
    l3Offset: 0,
    l3Proto: 'none',
    l4Offset: 0,
    l4Proto: 'none',
    ipv4HeaderLen: 0,
    ipv4TotalLength: 0,
    ipv6PayloadLength: 0,
    isFragment: false,
    capturedLen,
  }

  let offset = 0
  let etherType = 0

  switch (linkType) {
    case 1: { // Ethernet
      if (capturedLen < 14) return none
      offset = 12
      etherType = (data[offset]! << 8) | data[offset + 1]!
      while ((etherType === 0x8100 || etherType === 0x88a8) && offset + 4 <= capturedLen) {
        offset += 4
        etherType = (data[offset]! << 8) | data[offset + 1]!
      }
      offset += 2
      // T34 — skip MPLS / PPPoE for checksum L3 locate
      if (etherType === 0x8847 || etherType === 0x8848) {
        let labels = 0
        while (offset + 4 <= capturedLen && labels < 16) {
          const s = (data[offset + 2]! & 0x01) !== 0
          offset += 4
          labels++
          if (s) break
        }
        if (offset < capturedLen) {
          const nib = data[offset]! >> 4
          etherType = nib === 6 ? 0x86dd : nib === 4 ? 0x0800 : 0
        }
      } else if (etherType === 0x8863 || etherType === 0x8864) {
        if (offset + 6 <= capturedLen) {
          offset += 6 // PPPoE header
          if (offset + 2 <= capturedLen) {
            const ppp = (data[offset]! << 8) | data[offset + 1]!
            offset += 2
            if (ppp === 0x0021) etherType = 0x0800
            else if (ppp === 0x0057) etherType = 0x86dd
            else etherType = 0
          }
        }
      }
      break
    }
    case 113: {
      if (capturedLen < 16) return none
      etherType = (data[14]! << 8) | data[15]!
      offset = 16
      break
    }
    case 276: {
      if (capturedLen < 20) return none
      etherType = (data[0]! << 8) | data[1]!
      offset = 20
      break
    }
    case 0: // DLT_NULL
    case 108: { // DLT_LOOP
      if (capturedLen < 5) return none
      offset = 4
      {
        const ver = data[4]! >> 4
        etherType = ver === 6 ? 0x86dd : ver === 4 ? 0x0800 : 0
      }
      break
    }
    case 9: // PPP
    case 50: // PPP-HDLC
    case 104: { // Cisco HDLC
      offset = 0
      if (capturedLen >= 2 && data[0] === 0xff && data[1] === 0x03) offset = 2
      if (offset < capturedLen) {
        const proto =
          (data[offset]! & 1) !== 0
            ? data[offset]!
            : offset + 1 < capturedLen
              ? (data[offset]! << 8) | data[offset + 1]!
              : 0
        const skip = (data[offset]! & 1) !== 0 ? 1 : 2
        offset += skip
        if (proto === 0x0021) etherType = 0x0800
        else if (proto === 0x0057) etherType = 0x86dd
        else etherType = 0
      }
      break
    }
    case 101:
    case 228:
      etherType = 0x0800
      break
    case 229:
      etherType = 0x86dd
      break
    case 239: { // NFLOG — locate payload TLV (type 9) when present
      if (capturedLen < 4) return none
      let pos = 4
      let payloadOff = -1
      while (pos + 4 <= capturedLen) {
        const tlvLen = data[pos]! | (data[pos + 1]! << 8)
        const tlvType = data[pos + 2]! | (data[pos + 3]! << 8)
        const total = Math.max(4, (tlvLen + 3) & ~3)
        if (pos + total > capturedLen) break
        if (tlvType === 9 && tlvLen > 4) {
          payloadOff = pos + 4
          break
        }
        pos += total
      }
      if (payloadOff < 0 || payloadOff >= capturedLen) return none
      offset = payloadOff
      {
        const ver = data[offset]! >> 4
        etherType = ver === 6 ? 0x86dd : ver === 4 ? 0x0800 : 0
      }
      break
    }
    default:
      return none
  }

  const l2Offset = linkType === 1 ? 0 : linkType === 113 ? 0 : linkType === 276 ? 0 : 0
  const l3Offset = offset

  if (etherType === 0x0800) {
    if (l3Offset + 20 > capturedLen) return { ...none, l2Offset, l3Offset, l3Proto: 'none' }
    const ihl = (data[l3Offset]! & 0xf) * 4
    if (ihl < 20 || l3Offset + ihl > capturedLen) return { ...none, l2Offset, l3Offset }
    const totalLength = (data[l3Offset + 2]! << 8) | data[l3Offset + 3]!
    const fragOff = ((data[l3Offset + 6]! & 0x1f) << 8) | data[l3Offset + 7]!
    const mf = (data[l3Offset + 6]! & 0x20) !== 0
    const isFragment = fragOff > 0 || mf
    const ipProto = data[l3Offset + 9]!
    const l4Offset = l3Offset + ihl
    const l4Proto =
      ipProto === 6 ? 'tcp'
      : ipProto === 17 ? 'udp'
      : ipProto === 132 ? 'sctp'
      : ipProto === 1 ? 'icmpv4'
      : ipProto === 112 ? 'vrrp'
      : 'none'
    return {
      linkType,
      l2Offset,
      l3Offset,
      l3Proto: 'ipv4',
      l4Offset,
      l4Proto,
      ipv4HeaderLen: ihl,
      ipv4TotalLength: totalLength,
      ipv6PayloadLength: 0,
      isFragment,
      capturedLen,
    }
  }

  if (etherType === 0x86dd) {
    if (l3Offset + 40 > capturedLen) return { ...none, l2Offset, l3Offset }
    const ipv6PayloadLength = (data[l3Offset + 4]! << 8) | data[l3Offset + 5]!
    let nextHeader = data[l3Offset + 6]!
    let hdrOff = l3Offset + 40
    let isFragment = false
    let depth = 0
    while (depth < 8 && hdrOff < capturedLen) {
      if (nextHeader === 44) {
        if (hdrOff + 8 > capturedLen) break
        // Any Fragment Header means this packet is part of a fragmented datagram (CF-05),
        // including the first fragment (offset 0 with MF set).
        isFragment = true
        nextHeader = data[hdrOff]!
        hdrOff += 8
        depth++
      } else if (nextHeader === 0 || nextHeader === 43 || nextHeader === 60) {
        if (hdrOff + 2 > capturedLen) break
        const extLen = (data[hdrOff + 1]! + 1) * 8
        nextHeader = data[hdrOff]!
        hdrOff += extLen
        depth++
      } else if (nextHeader === 51) {
        if (hdrOff + 2 > capturedLen) break
        const ahLen = (data[hdrOff + 1]! + 2) * 4
        nextHeader = data[hdrOff]!
        hdrOff += ahLen
        depth++
      } else {
        break
      }
    }
    const l4Proto =
      nextHeader === 6 ? 'tcp'
      : nextHeader === 17 ? 'udp'
      : nextHeader === 132 ? 'sctp'
      : nextHeader === 58 ? 'icmpv6'
      : 'none'
    return {
      linkType,
      l2Offset,
      l3Offset,
      l3Proto: 'ipv6',
      l4Offset: hdrOff,
      l4Proto,
      ipv4HeaderLen: 0,
      ipv4TotalLength: 0,
      ipv6PayloadLength,
      isFragment,
      capturedLen,
    }
  }

  if (etherType === 0x0806) {
    return { ...none, l2Offset, l3Offset, l3Proto: 'arp' }
  }

  return { ...none, l2Offset, l3Offset }
}
