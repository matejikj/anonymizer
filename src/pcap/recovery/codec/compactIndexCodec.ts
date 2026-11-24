/**
 * Compact recovery index plaintext (v1) — typed-array arenas, no per-occurrence objects.
 *
 * Layout:
 *   magic "RCIDX001" (8)
 *   version u16
 *   header fields…
 *   dropped bitset + rank checkpoints
 *   string table
 *   entry arena u32[COMPACT_ENTRY_STRIDE]:
 *     categoryId, matchKind, anonCanStr, anonWireStr,
 *     originalCanStr, originalWireStr, occStart, occCount, protocolId, fieldId
 *   occurrence arena u32[COMPACT_OCC_STRIDE]:
 *     originalPn, anonPn, fileOffset, dataOffset, byteOff, byteLen, protocolId, fieldId, originalWireStrId
 *   range directory u32[6]: spanStart, spanEnd, fileOffset, length, dataFrameLocalIndex, split
 */

import { sha256 } from '../../../crypto/incrementalSha256'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import { RecoveryReader, RecoveryWriter } from './binaryIO'
import { categoryFromId, matchKindFromId } from './categoryIds'
import type { RecoveryLookupCategory, RecoveryMatchKind } from '../domain/types'
import type { SourceRangeEntry } from '../export/sourceFrameReader'

export const RECOVERY_COMPACT_INDEX_MAGIC = 'RCIDX001'
export const RECOVERY_COMPACT_INDEX_VERSION = 1

export const COMPACT_ENTRY_STRIDE = 10
export const COMPACT_OCC_STRIDE = 9
export const RANK_CHECKPOINT_EVERY = 64

export interface CompactIndexArenas {
  readonly entryU32: Uint32Array
  readonly occurrenceU32: Uint32Array
  readonly stringBytes: Uint8Array
  readonly stringOffsets: Uint32Array
  readonly stringLengths: Uint16Array
  readonly droppedBitset: Uint8Array
  readonly rankCheckpoints: Uint32Array
  readonly rangeDirectory: Uint32Array // stride 6: spanStart, spanEnd, fileOffset, length, dataFrameLocalIndex, split
}

export interface CompactIndexView {
  readonly generationId: string
  readonly mappingRevision: number
  readonly originalPacketCount: number
  readonly anonymizedPacketCount: number
  readonly entryCount: number
  readonly occurrenceCount: number
  readonly arenas: CompactIndexArenas
}

export function writeCompactIndex(input: {
  generationId: string
  mappingRevision: number
  originalPacketCount: number
  anonymizedPacketCount: number
  arenas: CompactIndexArenas
}): PcapRecoveryResult<Uint8Array> {
  if (input.arenas.entryU32.length / COMPACT_ENTRY_STRIDE > PCAP_RECOVERY_LIMITS.maxLookupEntries) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many lookup entries')
  }
  if (input.arenas.occurrenceU32.length / COMPACT_OCC_STRIDE > PCAP_RECOVERY_LIMITS.maxOccurrences) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many occurrences')
  }
  const w = new RecoveryWriter()
  w.writeBytes(new TextEncoder().encode(RECOVERY_COMPACT_INDEX_MAGIC))
  w.writeU16(RECOVERY_COMPACT_INDEX_VERSION)
  const gen = new TextEncoder().encode(input.generationId)
  w.writeU16(gen.byteLength)
  w.writeBytes(gen)
  w.writeU32(input.mappingRevision)
  w.writeU32(input.originalPacketCount)
  w.writeU32(input.anonymizedPacketCount)
  const entryCount = input.arenas.entryU32.length / COMPACT_ENTRY_STRIDE
  const occCount = input.arenas.occurrenceU32.length / COMPACT_OCC_STRIDE
  const stringCount = input.arenas.stringOffsets.length
  w.writeU32(entryCount)
  w.writeU32(occCount)
  w.writeU32(stringCount)
  w.writeU32(input.arenas.droppedBitset.byteLength)
  w.writeU32(input.arenas.rankCheckpoints.length)
  w.writeU32(input.arenas.rangeDirectory.length / 6)

  w.writeBytes(input.arenas.droppedBitset)
  w.writeBytes(
    new Uint8Array(
      input.arenas.rankCheckpoints.buffer,
      input.arenas.rankCheckpoints.byteOffset,
      input.arenas.rankCheckpoints.byteLength,
    ),
  )

  for (let i = 0; i < stringCount; i++) {
    const off = input.arenas.stringOffsets[i]!
    const len = input.arenas.stringLengths[i]!
    w.writeU16(len)
    w.writeBytes(input.arenas.stringBytes.subarray(off, off + len))
  }

  w.writeBytes(
    new Uint8Array(input.arenas.entryU32.buffer, input.arenas.entryU32.byteOffset, input.arenas.entryU32.byteLength),
  )
  w.writeBytes(
    new Uint8Array(
      input.arenas.occurrenceU32.buffer,
      input.arenas.occurrenceU32.byteOffset,
      input.arenas.occurrenceU32.byteLength,
    ),
  )
  w.writeBytes(
    new Uint8Array(
      input.arenas.rangeDirectory.buffer,
      input.arenas.rangeDirectory.byteOffset,
      input.arenas.rangeDirectory.byteLength,
    ),
  )

  const out = w.toUint8Array()
  if (out.byteLength > PCAP_RECOVERY_LIMITS.maxUnlockedIndexBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'compact index exceeds limit')
  }
  return recoveryOk(out)
}

export function parseCompactIndex(bytes: Uint8Array): PcapRecoveryResult<CompactIndexView> {
  if (bytes.byteLength > PCAP_RECOVERY_LIMITS.maxUnlockedIndexBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'compact index exceeds limit')
  }
  const r = new RecoveryReader(bytes)
  const magic = r.readBytes(8, 8)
  if (!magic.ok) return magic
  if (new TextDecoder().decode(magic.value) !== RECOVERY_COMPACT_INDEX_MAGIC) {
    return recoveryFail(PCAP_RECOVERY_ERROR.indexInvalid, 'invalid index magic')
  }
  const version = r.readU16()
  if (!version.ok) return version
  if (version.value !== RECOVERY_COMPACT_INDEX_VERSION) {
    return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, 'unsupported index version')
  }
  const genLen = r.readU16()
  if (!genLen.ok) return genLen
  const generationId = r.readUtf8(genLen.value, 256)
  if (!generationId.ok) return generationId
  const mappingRevision = r.readU32()
  if (!mappingRevision.ok) return mappingRevision
  const originalPacketCount = r.readU32()
  if (!originalPacketCount.ok) return originalPacketCount
  const anonymizedPacketCount = r.readU32()
  if (!anonymizedPacketCount.ok) return anonymizedPacketCount
  const entryCount = r.readU32()
  if (!entryCount.ok) return entryCount
  const occCount = r.readU32()
  if (!occCount.ok) return occCount
  const stringCount = r.readU32()
  if (!stringCount.ok) return stringCount
  const bitsetLen = r.readU32()
  if (!bitsetLen.ok) return bitsetLen
  const rankLen = r.readU32()
  if (!rankLen.ok) return rankLen
  const rangeCount = r.readU32()
  if (!rangeCount.ok) return rangeCount

  if (entryCount.value > PCAP_RECOVERY_LIMITS.maxLookupEntries) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many lookup entries')
  }
  if (occCount.value > PCAP_RECOVERY_LIMITS.maxOccurrences) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many occurrences')
  }

  const droppedBitset = r.readBytes(bitsetLen.value, Math.ceil(originalPacketCount.value / 8) + 64)
  if (!droppedBitset.ok) return droppedBitset
  const rankBytes = r.readBytes(rankLen.value * 4, rankLen.value * 4)
  if (!rankBytes.ok) return rankBytes
  const rankCheckpoints = new Uint32Array(
    rankBytes.value.buffer.slice(
      rankBytes.value.byteOffset,
      rankBytes.value.byteOffset + rankBytes.value.byteLength,
    ),
  )

  const stringOffsets = new Uint32Array(stringCount.value)
  const stringLengths = new Uint16Array(stringCount.value)
  const chunks: Uint8Array[] = []
  let total = 0
  for (let i = 0; i < stringCount.value; i++) {
    const len = r.readU16()
    if (!len.ok) return len
    const s = r.readBytes(len.value, PCAP_RECOVERY_LIMITS.maxStringBytes)
    if (!s.ok) return s
    stringOffsets[i] = total
    stringLengths[i] = len.value
    chunks.push(s.value)
    total += len.value
  }
  const stringBytes = new Uint8Array(total)
  for (let i = 0; i < chunks.length; i++) stringBytes.set(chunks[i]!, stringOffsets[i]!)

  const entryBytes = r.readBytes(entryCount.value * COMPACT_ENTRY_STRIDE * 4, entryCount.value * COMPACT_ENTRY_STRIDE * 4)
  if (!entryBytes.ok) return entryBytes
  const occBytes = r.readBytes(occCount.value * COMPACT_OCC_STRIDE * 4, occCount.value * COMPACT_OCC_STRIDE * 4)
  if (!occBytes.ok) return occBytes
  const rangeBytes = r.readBytes(rangeCount.value * 6 * 4, rangeCount.value * 6 * 4)
  if (!rangeBytes.ok) return rangeBytes
  const consumed = r.expectConsumed()
  if (!consumed.ok) return consumed

  return recoveryOk({
    generationId: generationId.value,
    mappingRevision: mappingRevision.value,
    originalPacketCount: originalPacketCount.value,
    anonymizedPacketCount: anonymizedPacketCount.value,
    entryCount: entryCount.value,
    occurrenceCount: occCount.value,
    arenas: {
      entryU32: new Uint32Array(
        entryBytes.value.buffer.slice(
          entryBytes.value.byteOffset,
          entryBytes.value.byteOffset + entryBytes.value.byteLength,
        ),
      ),
      occurrenceU32: new Uint32Array(
        occBytes.value.buffer.slice(
          occBytes.value.byteOffset,
          occBytes.value.byteOffset + occBytes.value.byteLength,
        ),
      ),
      stringBytes,
      stringOffsets,
      stringLengths,
      droppedBitset: droppedBitset.value,
      rankCheckpoints,
      rangeDirectory: new Uint32Array(
        rangeBytes.value.buffer.slice(
          rangeBytes.value.byteOffset,
          rangeBytes.value.byteOffset + rangeBytes.value.byteLength,
        ),
      ),
    },
  })
}

export function compactIndexSha256(plaintext: Uint8Array): Uint8Array {
  return sha256(plaintext)
}

export function splitCompactIndexFrames(
  plaintext: Uint8Array,
  maxFramePlaintextBytes: number,
): Uint8Array[] {
  const max = Math.min(maxFramePlaintextBytes, PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes)
  if (plaintext.byteLength <= max) return [plaintext]
  const parts: Uint8Array[] = []
  for (let off = 0; off < plaintext.byteLength; off += max) {
    parts.push(plaintext.subarray(off, Math.min(off + max, plaintext.byteLength)))
  }
  return parts
}

export function joinCompactIndexFrames(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.byteLength, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.byteLength
  }
  return out
}

export function compactStringAt(arenas: CompactIndexArenas, id: number): string {
  if (id === 0xffffffff) return ''
  const off = arenas.stringOffsets[id]!
  const len = arenas.stringLengths[id]!
  return new TextDecoder().decode(arenas.stringBytes.subarray(off, off + len))
}

export function entryCategory(
  arenas: CompactIndexArenas,
  entryIndex: number,
): RecoveryLookupCategory | null {
  return categoryFromId(arenas.entryU32[entryIndex * COMPACT_ENTRY_STRIDE]!)
}

export function entryMatchKind(
  arenas: CompactIndexArenas,
  entryIndex: number,
): RecoveryMatchKind | null {
  return matchKindFromId(arenas.entryU32[entryIndex * COMPACT_ENTRY_STRIDE + 1]!)
}

export function packRangeDirectory(entries: readonly SourceRangeEntry[]): Uint32Array {
  const out = new Uint32Array(entries.length * 6)
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]!
    const b = i * 6
    out[b] = e.spanStart >>> 0
    out[b + 1] = e.spanEnd >>> 0
    out[b + 2] = e.fileOffset >>> 0
    out[b + 3] = e.length >>> 0
    out[b + 4] = e.dataFrameLocalIndex >>> 0
    out[b + 5] = e.split ? 1 : 0
  }
  return out
}

/** anonymized packet number (1-based) from original packet index via dropped bitset + ranks. */
export function anonymizedPacketNumberFromBitset(
  droppedBitset: Uint8Array,
  rankCheckpoints: Uint32Array,
  originalPacketIndex: number,
  originalPacketCount: number,
): number | null {
  if (originalPacketIndex < 0 || originalPacketIndex >= originalPacketCount) return null
  const byte = droppedBitset[originalPacketIndex >> 3] ?? 0
  if ((byte & (1 << (originalPacketIndex & 7))) !== 0) return null
  const checkpoint = Math.floor(originalPacketIndex / RANK_CHECKPOINT_EVERY)
  let anon = rankCheckpoints[checkpoint] ?? 0
  const start = checkpoint * RANK_CHECKPOINT_EVERY
  for (let i = start; i < originalPacketIndex; i++) {
    const b = droppedBitset[i >> 3] ?? 0
    if ((b & (1 << (i & 7))) === 0) anon += 1
  }
  return anon + 1
}

export function buildRankCheckpoints(
  droppedBitset: Uint8Array,
  originalPacketCount: number,
): Uint32Array {
  const count = Math.ceil(originalPacketCount / RANK_CHECKPOINT_EVERY) || 1
  const ranks = new Uint32Array(count)
  let kept = 0
  for (let i = 0; i < originalPacketCount; i++) {
    if (i % RANK_CHECKPOINT_EVERY === 0) {
      ranks[i / RANK_CHECKPOINT_EVERY] = kept
    }
    const b = droppedBitset[i >> 3] ?? 0
    if ((b & (1 << (i & 7))) === 0) kept += 1
  }
  return ranks
}
