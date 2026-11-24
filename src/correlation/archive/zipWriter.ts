/**
 * T44 — ZIP store writer (no deflate dependency). Neutral timestamps; IEEE CRC-32.
 */

import { crc32, writeCrc32Le } from '../../crypto/crc32.ts'

export interface ZipWriteEntry {
  /** Safe relative path using `/` separators (already validated alias). */
  readonly path: string
  readonly data: Uint8Array
}

function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

function u16le(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff])
}

function u32le(n: number): Uint8Array {
  return new Uint8Array([
    n & 0xff,
    (n >>> 8) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 24) & 0xff,
  ])
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.byteLength
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.byteLength
  }
  return out
}

/**
 * Build a ZIP archive (store method only). Paths must already be safe aliases.
 */
export function buildZipStoreArchive(entries: readonly ZipWriteEntry[]): Uint8Array {
  const localParts: Uint8Array[] = []
  const centralParts: Uint8Array[] = []
  let offset = 0

  for (const entry of entries) {
    const name = encodeUtf8(entry.path)
    const data = entry.data
    const crc = crc32(data)
    const local = concat([
      u32le(0x04034b50),
      u16le(20), // version needed
      u16le(0), // flags
      u16le(0), // store
      u16le(0), // time
      u16le(0), // date — neutral
      u32le(crc),
      u32le(data.byteLength),
      u32le(data.byteLength),
      u16le(name.byteLength),
      u16le(0), // extra
      name,
      data,
    ])
    localParts.push(local)

    const central = concat([
      u32le(0x02014b50),
      u16le(20), // version made by
      u16le(20), // version needed
      u16le(0),
      u16le(0),
      u16le(0),
      u16le(0),
      u32le(crc),
      u32le(data.byteLength),
      u32le(data.byteLength),
      u16le(name.byteLength),
      u16le(0),
      u16le(0), // comment
      u16le(0), // disk
      u16le(0), // int attrs
      u32le(0), // ext attrs
      u32le(offset),
      name,
    ])
    centralParts.push(central)
    offset += local.byteLength
  }

  const centralDir = concat(centralParts)
  const eocd = concat([
    u32le(0x06054b50),
    u16le(0),
    u16le(0),
    u16le(entries.length),
    u16le(entries.length),
    u32le(centralDir.byteLength),
    u32le(offset),
    u16le(0),
  ])

  return concat([...localParts, centralDir, eocd])
}

/** Re-export for tests that verify CRC of written members. */
export { crc32, writeCrc32Le }
