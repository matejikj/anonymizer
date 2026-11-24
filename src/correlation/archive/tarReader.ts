/**
 * T44 — ustar TAR reader (regular files + directories only). No symlink follow.
 */

import { ARCHIVE_LIMITS } from './limits.ts'
import { validateArchivePath } from './pathSafety.ts'

const BLOCK = 512

export type TarReadErrorCode =
  | 'tar-truncated'
  | 'tar-checksum'
  | 'tar-unsupported-type'
  | 'tar-path'
  | 'tar-bomb'
  | 'tar-too-many-entries'
  | 'cancelled'

export class TarReadError extends Error {
  readonly code: TarReadErrorCode
  constructor(code: TarReadErrorCode) {
    super(code)
    this.name = 'TarReadError'
    this.code = code
  }
}

export interface TarMember {
  readonly relativePath: string
  readonly isDirectory: boolean
  readonly data: Uint8Array
}

function readOctal(bytes: Uint8Array, offset: number, length: number): number {
  let s = ''
  for (let i = 0; i < length; i++) {
    const c = bytes[offset + i]!
    if (c === 0 || c === 0x20) continue
    s += String.fromCharCode(c)
  }
  if (s.length === 0) return 0
  const n = Number.parseInt(s, 8)
  return Number.isFinite(n) ? n : NaN
}

function tarChecksumOk(block: Uint8Array): boolean {
  const stored = readOctal(block, 148, 8)
  if (!Number.isFinite(stored)) return false
  let sum = 0
  for (let i = 0; i < BLOCK; i++) {
    sum += i >= 148 && i < 156 ? 0x20 : block[i]!
  }
  return sum === stored
}

function isZeroBlock(block: Uint8Array): boolean {
  for (let i = 0; i < BLOCK; i++) {
    if (block[i] !== 0) return false
  }
  return true
}

export function looksLikeUstar(head: Uint8Array): boolean {
  if (head.byteLength < 262) return false
  // "ustar\0" or "ustar "
  return (
    head[257] === 0x75
    && head[258] === 0x73
    && head[259] === 0x74
    && head[260] === 0x61
    && head[261] === 0x72
  )
}

export function readTarArchive(
  bytes: Uint8Array,
  options: { readonly signal?: AbortSignal } = {},
): readonly TarMember[] {
  const members: TarMember[] = []
  let offset = 0
  let inflatedTotal = 0
  let entries = 0
  let longName: string | null = null

  while (offset + BLOCK <= bytes.byteLength) {
    if (options.signal?.aborted) throw new TarReadError('cancelled')
    const header = bytes.subarray(offset, offset + BLOCK)
    offset += BLOCK
    if (isZeroBlock(header)) {
      // End of archive: optional second zero block
      break
    }
    if (!tarChecksumOk(header)) throw new TarReadError('tar-checksum')

    entries += 1
    if (entries > ARCHIVE_LIMITS.maxEntriesScanned) throw new TarReadError('tar-too-many-entries')

    const nameField = new TextDecoder('utf-8', { fatal: false })
      .decode(header.subarray(0, 100))
      .replace(/\0.*$/, '')
    const prefix = new TextDecoder('utf-8', { fatal: false })
      .decode(header.subarray(345, 500))
      .replace(/\0.*$/, '')
    const typeflag = header[156]!
    const size = readOctal(header, 124, 12)
    if (!Number.isFinite(size) || size < 0) throw new TarReadError('tar-truncated')

    const dataBlocks = Math.ceil(size / BLOCK)
    const dataEnd = offset + dataBlocks * BLOCK
    if (dataEnd > bytes.byteLength) throw new TarReadError('tar-truncated')
    const data = bytes.subarray(offset, offset + size)
    offset = dataEnd

    // GNU long name
    if (typeflag === 0x4c /* 'L' */) {
      longName = new TextDecoder('utf-8', { fatal: false }).decode(data).replace(/\0.*$/, '')
      continue
    }
    // PAX extended header — skip body; do not trust uname/path overrides for identity (omit path override for safety)
    if (typeflag === 0x78 /* 'x' */ || typeflag === 0x67 /* 'g' */) {
      longName = null
      continue
    }

    let rawName = longName ?? (prefix ? `${prefix}/${nameField}` : nameField)
    longName = null

    // Regular file / directory only
    if (typeflag === 0x35 /* '5' */ || rawName.endsWith('/')) {
      const path = validateArchivePath(rawName.endsWith('/') ? rawName : `${rawName}/`)
      if (!path.ok) throw new TarReadError('tar-path')
      members.push({ relativePath: path.relative, isDirectory: true, data: new Uint8Array(0) })
      continue
    }
    if (typeflag !== 0x30 /* '0' */ && typeflag !== 0x00) {
      // symlink / hardlink / device / fifo / sparse
      throw new TarReadError('tar-unsupported-type')
    }

    const path = validateArchivePath(rawName)
    if (!path.ok) throw new TarReadError('tar-path')
    if (size > ARCHIVE_LIMITS.maxSingleEntryBytes) throw new TarReadError('tar-bomb')
    if (inflatedTotal + size > ARCHIVE_LIMITS.maxTotalInflatedBytes) throw new TarReadError('tar-bomb')
    inflatedTotal += size
    members.push({ relativePath: path.relative, isDirectory: false, data: data.slice() })
  }

  return members
}
