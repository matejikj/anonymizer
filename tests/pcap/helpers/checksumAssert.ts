/**
 * Independent checksum oracle for CF-07 — does not trust preview/export skip sets.
 */

import { expect } from 'vitest'
import { locateLayers } from '../../../src/pcap/checksums/locate'
import {
  finalizeChecksum,
  onesComplementSum,
  verifyChecksum,
} from '../../../src/pcap/checksums/onesComplement'

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

export function assertPacketChecksumsValid(data: Uint8Array, linkType: number): void {
  const layers = locateLayers(data, linkType, data.length)
  if (layers.l3Proto === 'ipv4') {
    const ok = verifyChecksum(
      data,
      layers.l3Offset,
      layers.l3Offset + layers.ipv4HeaderLen,
      layers.l3Offset + 10,
    )
    expect(ok, 'IPv4 header checksum must verify independently').toBe(true)
  }

  if (layers.isFragment || layers.l4Proto === 'none' || layers.l3Proto !== 'ipv4') return

  const srcOff = layers.l3Offset + 12
  const dstOff = layers.l3Offset + 16
  const payloadLen = data.length - layers.l4Offset

  if (layers.l4Proto === 'udp' && layers.l4Offset + 8 <= data.length) {
    const csumOff = layers.l4Offset + 6
    const stored = (data[csumOff]! << 8) | data[csumOff + 1]!
    if (stored === 0) return // UDP checksum optional on IPv4
    const copy = data.slice()
    copy[csumOff] = 0
    copy[csumOff + 1] = 0
    let sum = pseudoHeaderSumIpv4(copy, srcOff, dstOff, 17, payloadLen)
    sum += onesComplementSum(copy, layers.l4Offset, data.length)
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
    const expected = finalizeChecksum(sum)
    expect(stored, 'UDP checksum must match independent recomputation').toBe(expected === 0 ? 0xffff : expected)
  }

  if (layers.l4Proto === 'tcp' && layers.l4Offset + 20 <= data.length) {
    const csumOff = layers.l4Offset + 16
    const stored = (data[csumOff]! << 8) | data[csumOff + 1]!
    const copy = data.slice()
    copy[csumOff] = 0
    copy[csumOff + 1] = 0
    let sum = pseudoHeaderSumIpv4(copy, srcOff, dstOff, 6, payloadLen)
    sum += onesComplementSum(copy, layers.l4Offset, data.length)
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
    const expected = finalizeChecksum(sum)
    expect(stored, 'TCP checksum must match independent recomputation').toBe(expected === 0 ? 0xffff : expected)
  }
}
