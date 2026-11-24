/**
 * T44 — ZIP reader (store + deflate-raw). No ZIP64, no encryption, path-safe members only.
 */

import { crc32 } from '../../crypto/crc32.ts'
import { ARCHIVE_LIMITS } from './limits.ts'
import { validateArchivePath } from './pathSafety.ts'
import { InflateRawError, inflateDeflateRaw } from './inflateRaw.ts'

const SIG_LOCAL = 0x04034b50
const SIG_CENTRAL = 0x02014b50
const SIG_EOCD = 0x06054b50
const METHOD_STORE = 0
const METHOD_DEFLATE = 8

export type ZipReadErrorCode =
  | 'zip-truncated'
  | 'zip-encrypted'
  | 'zip-unsupported-method'
  | 'zip-zip64'
  | 'zip-crc'
  | 'zip-bomb'
  | 'zip-path'
  | 'zip-too-many-entries'
  | 'deflate-unsupported-api'
  | 'cancelled'

export class ZipReadError extends Error {
  readonly code: ZipReadErrorCode
  constructor(code: ZipReadErrorCode) {
    super(code)
    this.name = 'ZipReadError'
    this.code = code
  }
}

export interface ZipMember {
  /** Validated relative path (empty for directory-only). */
  readonly relativePath: string
  readonly isDirectory: boolean
  readonly data: Uint8Array
}

function u16(view: DataView, o: number): number {
  return view.getUint16(o, true)
}
function u32(view: DataView, o: number): number {
  return view.getUint32(o, true)
}

function findEocd(bytes: Uint8Array): number {
  // EOCD is at least 22 bytes; comment up to 64 KiB
  const min = Math.max(0, bytes.byteLength - (22 + 0xffff))
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  for (let i = bytes.byteLength - 22; i >= min; i--) {
    if (view.getUint32(i, true) === SIG_EOCD) return i
  }
  return -1
}

export async function readZipArchive(
  bytes: Uint8Array,
  options: { readonly signal?: AbortSignal } = {},
): Promise<readonly ZipMember[]> {
  if (bytes.byteLength < 22) throw new ZipReadError('zip-truncated')
  const eocdOff = findEocd(bytes)
  if (eocdOff < 0) throw new ZipReadError('zip-truncated')

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const commentLen = u16(view, eocdOff + 20)
  if (commentLen > ARCHIVE_LIMITS.maxCommentBytes) throw new ZipReadError('zip-truncated')
  const totalEntries = u16(view, eocdOff + 10)
  const cdSize = u32(view, eocdOff + 12)
  const cdOffset = u32(view, eocdOff + 16)
  if (totalEntries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new ZipReadError('zip-zip64')
  }
  if (totalEntries > ARCHIVE_LIMITS.maxEntriesScanned) {
    throw new ZipReadError('zip-too-many-entries')
  }
  if (cdOffset + cdSize > bytes.byteLength) throw new ZipReadError('zip-truncated')

  const members: ZipMember[] = []
  let pos = cdOffset
  let inflatedTotal = 0

  for (let n = 0; n < totalEntries; n++) {
    if (options.signal?.aborted) throw new ZipReadError('cancelled')
    if (pos + 46 > bytes.byteLength) throw new ZipReadError('zip-truncated')
    if (u32(view, pos) !== SIG_CENTRAL) throw new ZipReadError('zip-truncated')

    const flags = u16(view, pos + 8)
    const method = u16(view, pos + 10)
    const crcExpected = u32(view, pos + 16)
    const compSize = u32(view, pos + 20)
    const uncompSize = u32(view, pos + 24)
    const nameLen = u16(view, pos + 28)
    const extraLen = u16(view, pos + 30)
    const commentLenEntry = u16(view, pos + 32)
    const localHeaderOffset = u32(view, pos + 42)

    if (flags & 0x0001) throw new ZipReadError('zip-encrypted')
    if (compSize === 0xffffffff || uncompSize === 0xffffffff || localHeaderOffset === 0xffffffff) {
      throw new ZipReadError('zip-zip64')
    }

    const nameStart = pos + 46
    const nameEnd = nameStart + nameLen
    if (nameEnd + extraLen + commentLenEntry > bytes.byteLength) {
      throw new ZipReadError('zip-truncated')
    }
    const nameBytes = bytes.subarray(nameStart, nameEnd)
    const name = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes)
    const path = validateArchivePath(name)
    if (!path.ok) throw new ZipReadError('zip-path')

    pos = nameEnd + extraLen + commentLenEntry

    if (path.isDirectory || (uncompSize === 0 && name.endsWith('/'))) {
      members.push({ relativePath: path.relative, isDirectory: true, data: new Uint8Array(0) })
      continue
    }

    if (uncompSize > ARCHIVE_LIMITS.maxSingleEntryBytes) throw new ZipReadError('zip-bomb')
    if (inflatedTotal + uncompSize > ARCHIVE_LIMITS.maxTotalInflatedBytes) {
      throw new ZipReadError('zip-bomb')
    }

    // Local header
    const lh = localHeaderOffset
    if (lh + 30 > bytes.byteLength || u32(view, lh) !== SIG_LOCAL) {
      throw new ZipReadError('zip-truncated')
    }
    const localNameLen = u16(view, lh + 26)
    const localExtraLen = u16(view, lh + 28)
    const dataOff = lh + 30 + localNameLen + localExtraLen
    if (dataOff + compSize > bytes.byteLength) throw new ZipReadError('zip-truncated')
    const compressed = bytes.subarray(dataOff, dataOff + compSize)

    let data: Uint8Array
    if (method === METHOD_STORE) {
      data = compressed.slice()
    } else if (method === METHOD_DEFLATE) {
      try {
        data = await inflateDeflateRaw(compressed, {
          maxInflatedBytes: Math.min(
            ARCHIVE_LIMITS.maxSingleEntryBytes,
            uncompSize > 0 ? uncompSize : ARCHIVE_LIMITS.maxSingleEntryBytes,
          ),
          compressedBytesForRatio: compSize,
          signal: options.signal,
        })
      } catch (err) {
        if (err instanceof InflateRawError) {
          if (err.code === 'archive-bomb') throw new ZipReadError('zip-bomb')
          if (err.code === 'deflate-unsupported-api') throw new ZipReadError('deflate-unsupported-api')
          if (err.code === 'cancelled') throw new ZipReadError('cancelled')
          throw new ZipReadError('zip-truncated')
        }
        throw new ZipReadError('zip-truncated')
      }
    } else {
      throw new ZipReadError('zip-unsupported-method')
    }

    if (uncompSize > 0 && data.byteLength !== uncompSize) throw new ZipReadError('zip-truncated')
    if (crc32(data) !== crcExpected) throw new ZipReadError('zip-crc')

    inflatedTotal += data.byteLength
    members.push({ relativePath: path.relative, isDirectory: false, data })
  }

  void SIG_CENTRAL
  return members
}

export function looksLikeZip(head: Uint8Array): boolean {
  return (
    head.byteLength >= 4
    && head[0] === 0x50
    && head[1] === 0x4b
    && head[2] === 0x03
    && head[3] === 0x04
  )
}
