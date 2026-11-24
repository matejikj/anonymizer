/**
 * IEEE CRC-32 (PKZIP / Ethernet) — polynomial 0xEDB88320 (reflected).
 * Distinct from CRC32c (Castagnoli) used by SCTP.
 */

const TABLE = (() => {
  const poly = 0xedb88320
  const t = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let k = 0; k < 8; k++) c = c & 1 ? poly ^ (c >>> 1) : c >>> 1
    t[i] = c >>> 0
  }
  return t
})()

/** IEEE CRC-32 over `bytes[offset .. offset+length)`. */
export function crc32(
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

export function writeCrc32Le(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = value & 0xff
  buf[offset + 1] = (value >>> 8) & 0xff
  buf[offset + 2] = (value >>> 16) & 0xff
  buf[offset + 3] = (value >>> 24) & 0xff
}
