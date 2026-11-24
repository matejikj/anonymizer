/**
 * CRC32c (Castagnoli) — used by SCTP (RFC 9260) and similar transports.
 * Polynomial 0x1EDC6F41; table uses reflected form 0x82F63B78.
 */

const TABLE = (() => {
  const poly = 0x82f63b78
  const t = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let k = 0; k < 8; k++) c = c & 1 ? poly ^ (c >>> 1) : c >>> 1
    t[i] = c >>> 0
  }
  return t
})()

/** CRC32c over `bytes[offset .. offset+length)`. */
export function crc32c(
  bytes: Uint8Array,
  offset = 0,
  length = bytes.byteLength - offset,
): number {
  let crc = 0xffffffff
  const end = offset + length
  for (let i = offset; i < end; i++) {
    crc = TABLE[(crc ^ bytes[i]!) & 0xff]! ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

/** Write CRC32c into a 4-byte field (little-endian — SCTP wire convention). */
export function writeCrc32cLe(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = value & 0xff
  buf[offset + 1] = (value >>> 8) & 0xff
  buf[offset + 2] = (value >>> 16) & 0xff
  buf[offset + 3] = (value >>> 24) & 0xff
}

export function readCrc32cLe(buf: Uint8Array, offset: number): number {
  return (
    (buf[offset]!
      | (buf[offset + 1]! << 8)
      | (buf[offset + 2]! << 16)
      | (buf[offset + 3]! << 24))
    >>> 0
  )
}

/**
 * Compute SCTP common-header checksum over a packet with the checksum field
 * treated as zero (RFC 9260 §6.8).
 */
export function sctpCrc32c(packet: Uint8Array, offset: number, length: number): number {
  if (length < 12) return 0
  const end = offset + length
  // Sum with checksum bytes (offset+8..+12) as zero without mutating.
  let crc = 0xffffffff
  for (let i = offset; i < offset + 8; i++) {
    crc = TABLE[(crc ^ packet[i]!) & 0xff]! ^ (crc >>> 8)
  }
  for (let i = 0; i < 4; i++) {
    crc = TABLE[(crc ^ 0) & 0xff]! ^ (crc >>> 8)
  }
  for (let i = offset + 12; i < end; i++) {
    crc = TABLE[(crc ^ packet[i]!) & 0xff]! ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}
