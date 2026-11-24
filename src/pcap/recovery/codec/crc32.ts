/**
 * IEEE CRC-32 (ISO 3309) — integrity hint only, not authentication.
 */

const TABLE = (() => {
  const table = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let j = 0; j < 8; j++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    }
    table[i] = c >>> 0
  }
  return table
})()

export function crc32(bytes: Uint8Array, offset = 0, length = bytes.byteLength - offset): number {
  let c = 0xffffffff
  const end = offset + length
  for (let i = offset; i < end; i++) {
    c = TABLE[(c ^ bytes[i]!) & 0xff]! ^ (c >>> 8)
  }
  return (c ^ 0xffffffff) >>> 0
}
