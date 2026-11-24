/**
 * One's-complement Internet checksum (RFC 1071).
 */

export function onesComplementSum(data: Uint8Array, start: number, end: number): number {
  let sum = 0
  let i = start
  while (i + 1 < end) {
    sum += (data[i]! << 8) | data[i + 1]!
    i += 2
  }
  if (i < end) {
    sum += data[i]! << 8
  }
  while (sum > 0xffff) {
    sum = (sum & 0xffff) + (sum >> 16)
  }
  return sum
}

export function finalizeChecksum(sum: number): number {
  return (~sum) & 0xffff
}

export function computeChecksum(data: Uint8Array, start: number, end: number, zeroOffset?: number): number {
  let sum = onesComplementSum(data, start, end)
  if (zeroOffset !== undefined) {
    // Exclude checksum field (treated as zero during computation)
    const hi = data[zeroOffset]!
    const lo = data[zeroOffset + 1]!
    sum -= (hi << 8) | lo
    if (sum < 0) sum = (sum & 0xffff) + ((sum >> 16) & 0xffff)
  }
  return finalizeChecksum(sum)
}

/** RFC 1624 incremental update for a single 16-bit word change. */
export function rfc1624Update(oldChecksum: number, oldWord: number, newWord: number): number {
  let hc = ~oldChecksum & 0xffff
  hc = (hc + (~oldWord & 0xffff) + (newWord & 0xffff)) & 0xffff
  while (hc > 0xffff) hc = (hc & 0xffff) + (hc >> 16)
  return (~hc) & 0xffff
}

export function verifyChecksum(data: Uint8Array, start: number, end: number, checksumOffset: number): boolean {
  const stored = (data[checksumOffset]! << 8) | data[checksumOffset + 1]!
  if (stored === 0) return true // zero = disabled / not computed
  const computed = computeChecksum(data, start, end, checksumOffset)
  return stored === computed
}

export function writeChecksum(data: Uint8Array, offset: number, value: number): void {
  data[offset] = (value >> 8) & 0xff
  data[offset + 1] = value & 0xff
}
