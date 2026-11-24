/**
 * Hydrate RecoveryIndexSeed from sourceBlob spans into compact typed-array arenas.
 * No per-occurrence JS objects in the final index.
 */

import { wipeBytes } from '../../../crypto/wipe'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import {
  COMPACT_ENTRY_STRIDE,
  COMPACT_OCC_STRIDE,
  buildRankCheckpoints,
  packRangeDirectory,
  type CompactIndexArenas,
  type CompactIndexView,
  writeCompactIndex,
} from '../codec/compactIndexCodec'
import { matchKindId } from '../codec/categoryIds'
import type { SourceRangeEntry } from './sourceFrameReader'
import {
  parseRecoveryIndexSeed,
  seedStringAt,
  SEED_ENTRY_STRIDE,
  SEED_OCC_STRIDE,
  type ParsedRecoveryIndexSeed,
} from './recoveryIndexSeedPort'

export interface BuildCompactIndexInput {
  readonly indexSeed: ArrayBuffer
  readonly sourceBlob: Blob
  readonly rangeDirectory: readonly SourceRangeEntry[]
  readonly isCancelled?: () => boolean
}

export interface BuildCompactIndexResult {
  readonly view: CompactIndexView
  readonly plaintext: Uint8Array
}

function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0')
  }
  return out
}

function wireTextOrHex(bytes: Uint8Array): string {
  // Prefer UTF-8 for printable text fields; otherwise lossless hex.
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    if (text.length > 0 && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(text)) return text
  } catch {
    /* binary */
  }
  return bytesToHex(bytes)
}

class StringInterner {
  private readonly map = new Map<string, number>()
  private readonly chunks: Uint8Array[] = []
  private total = 0
  private readonly encoder = new TextEncoder()

  intern(s: string): number {
    const existing = this.map.get(s)
    if (existing !== undefined) return existing
    const b = this.encoder.encode(s)
    if (b.byteLength > PCAP_RECOVERY_LIMITS.maxStringBytes) {
      throw new CompactIndexBuildError(PCAP_RECOVERY_ERROR.oversize, 'string exceeds limit')
    }
    const id = this.chunks.length
    this.map.set(s, id)
    this.chunks.push(b)
    this.total += b.byteLength
    return id
  }

  finish(): { stringBytes: Uint8Array; stringOffsets: Uint32Array; stringLengths: Uint16Array } {
    const stringBytes = new Uint8Array(this.total)
    const stringOffsets = new Uint32Array(this.chunks.length)
    const stringLengths = new Uint16Array(this.chunks.length)
    let off = 0
    for (let i = 0; i < this.chunks.length; i++) {
      const c = this.chunks[i]!
      stringOffsets[i] = off
      stringLengths[i] = c.byteLength
      stringBytes.set(c, off)
      off += c.byteLength
    }
    return { stringBytes, stringOffsets, stringLengths }
  }
}

class CompactIndexBuildError extends Error {
  readonly code: typeof PCAP_RECOVERY_ERROR[keyof typeof PCAP_RECOVERY_ERROR]
  constructor(code: typeof PCAP_RECOVERY_ERROR[keyof typeof PCAP_RECOVERY_ERROR], message: string) {
    super(message)
    this.name = 'CompactIndexBuildError'
    this.code = code
  }
}

async function readSourceSpan(
  blob: Blob,
  absoluteOffset: number,
  byteLength: number,
): Promise<PcapRecoveryResult<Uint8Array>> {
  if (byteLength < 0 || byteLength > PCAP_RECOVERY_LIMITS.maxStringBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'occurrence span too large')
  }
  if (absoluteOffset < 0 || absoluteOffset + byteLength > blob.size) {
    return recoveryFail(PCAP_RECOVERY_ERROR.indexInvalid, 'occurrence span out of file')
  }
  const slice = blob.slice(absoluteOffset, absoluteOffset + byteLength)
  const ab = await slice.arrayBuffer()
  return recoveryOk(new Uint8Array(ab))
}

/**
 * Build compact INDEX plaintext from a transferable seed + source spans.
 * Wipes the seed buffer after parse.
 */
export async function buildCompactIndexFromSeed(
  input: BuildCompactIndexInput,
): Promise<PcapRecoveryResult<BuildCompactIndexResult>> {
  const seedBytes = new Uint8Array(input.indexSeed)
  let parsed: ParsedRecoveryIndexSeed
  try {
    const seed = parseRecoveryIndexSeed(input.indexSeed)
    if (!seed.ok) return seed
    parsed = seed.value
  } finally {
    wipeBytes(seedBytes)
  }

  if (input.isCancelled?.()) {
    return recoveryFail(PCAP_RECOVERY_ERROR.cancelled, 'cancelled')
  }

  try {
    const intern = new StringInterner()
    const entryU32 = new Uint32Array(parsed.entryCount * COMPACT_ENTRY_STRIDE)
    const occurrenceU32 = new Uint32Array(parsed.occurrenceCount * COMPACT_OCC_STRIDE)
    const seedEntry = parsed.arenas.entryU32
    const seedOcc = parsed.arenas.occurrenceU32

    // Track distinct originals per anonymized key for ambiguity.
    const originalsByAnon = new Map<string, Set<string>>()

    for (let e = 0; e < parsed.entryCount; e++) {
      if (input.isCancelled?.()) {
        return recoveryFail(PCAP_RECOVERY_ERROR.cancelled, 'cancelled')
      }
      const sb = e * SEED_ENTRY_STRIDE
      const categoryId = seedEntry[sb]!
      const matchKind = seedEntry[sb + 1]!
      const anonCanId = seedEntry[sb + 2]!
      const anonWireId = seedEntry[sb + 3]!
      const occStart = seedEntry[sb + 4]!
      const occCount = seedEntry[sb + 5]!
      const protocolId = seedEntry[sb + 6]!
      const fieldId = seedEntry[sb + 7]!

      const anonCan = seedStringAt(parsed.arenas, anonCanId)
      const anonWire = seedStringAt(parsed.arenas, anonWireId)
      const compactAnonCan = intern.intern(anonCan)
      const compactAnonWire = intern.intern(anonWire)

      let firstOriginalCan = 0xffffffff
      let firstOriginalWire = 0xffffffff
      const distinctOriginals = new Set<string>()

      for (let i = 0; i < occCount; i++) {
        const so = (occStart + i) * SEED_OCC_STRIDE
        const originalPacketNumber = seedOcc[so]!
        const anonymizedPacketNumber = seedOcc[so + 1]!
        const fileOffset = seedOcc[so + 2]!
        const dataOffset = seedOcc[so + 3]!
        const byteOffsetInPacket = seedOcc[so + 4]!
        const byteLength = seedOcc[so + 5]!
        const occProtocol = seedOcc[so + 6]!
        const occField = seedOcc[so + 7]!

        const absolute = (dataOffset + byteOffsetInPacket) >>> 0
        const span = await readSourceSpan(input.sourceBlob, absolute, byteLength)
        if (!span.ok) return span
        const originalText = wireTextOrHex(span.value)
        wipeBytes(span.value)
        const originalId = intern.intern(originalText)
        distinctOriginals.add(originalText)
        if (firstOriginalCan === 0xffffffff) {
          firstOriginalCan = originalId
          firstOriginalWire = originalId
        }

        const co = (occStart + i) * COMPACT_OCC_STRIDE
        occurrenceU32[co] = originalPacketNumber
        occurrenceU32[co + 1] = anonymizedPacketNumber
        occurrenceU32[co + 2] = fileOffset
        occurrenceU32[co + 3] = dataOffset
        occurrenceU32[co + 4] = byteOffsetInPacket
        occurrenceU32[co + 5] = byteLength
        occurrenceU32[co + 6] = occProtocol
        occurrenceU32[co + 7] = occField
        occurrenceU32[co + 8] = originalId
      }

      let set = originalsByAnon.get(anonCan)
      if (!set) {
        set = new Set()
        originalsByAnon.set(anonCan, set)
      }
      for (const o of distinctOriginals) set.add(o)

      let finalMatch = matchKind
      if (distinctOriginals.size > 1) {
        finalMatch = matchKindId('ambiguous')
      }

      const cb = e * COMPACT_ENTRY_STRIDE
      entryU32[cb] = categoryId
      entryU32[cb + 1] = finalMatch
      entryU32[cb + 2] = compactAnonCan
      entryU32[cb + 3] = compactAnonWire
      entryU32[cb + 4] = firstOriginalCan
      entryU32[cb + 5] = firstOriginalWire
      entryU32[cb + 6] = occStart
      entryU32[cb + 7] = occCount
      entryU32[cb + 8] = protocolId
      entryU32[cb + 9] = fieldId
    }

    const strings = intern.finish()

    // Cross-entry ambiguity: same anonymized mask maps to multiple originals.
    for (let e = 0; e < parsed.entryCount; e++) {
      const cb = e * COMPACT_ENTRY_STRIDE
      const anonId = entryU32[cb + 2]!
      const off = strings.stringOffsets[anonId]!
      const len = strings.stringLengths[anonId]!
      const anonCan = new TextDecoder().decode(strings.stringBytes.subarray(off, off + len))
      if ((originalsByAnon.get(anonCan)?.size ?? 0) > 1) {
        entryU32[cb + 1] = matchKindId('ambiguous')
      }
    }

    const rankCheckpoints = buildRankCheckpoints(parsed.droppedBitset, parsed.originalPacketCount)
    const rangeDirectory = packRangeDirectory(input.rangeDirectory)

    const arenas: CompactIndexArenas = {
      entryU32,
      occurrenceU32,
      stringBytes: strings.stringBytes,
      stringOffsets: strings.stringOffsets,
      stringLengths: strings.stringLengths,
      droppedBitset: parsed.droppedBitset,
      rankCheckpoints,
      rangeDirectory,
    }

    const view: CompactIndexView = {
      generationId: parsed.generationId,
      mappingRevision: parsed.mappingRevision,
      originalPacketCount: parsed.originalPacketCount,
      anonymizedPacketCount: parsed.anonymizedPacketCount,
      entryCount: parsed.entryCount,
      occurrenceCount: parsed.occurrenceCount,
      arenas,
    }

    const plaintext = writeCompactIndex({
      generationId: view.generationId,
      mappingRevision: view.mappingRevision,
      originalPacketCount: view.originalPacketCount,
      anonymizedPacketCount: view.anonymizedPacketCount,
      arenas,
    })
    if (!plaintext.ok) return plaintext

    return recoveryOk({ view, plaintext: plaintext.value })
  } catch (err) {
    if (err instanceof CompactIndexBuildError) {
      return recoveryFail(err.code, err.message)
    }
    return recoveryFail(
      PCAP_RECOVERY_ERROR.internal,
      err instanceof Error ? err.message : String(err),
    )
  }
}

/** Empty compact index (no seed) — still carries range directory when provided. */
export function buildEmptyCompactIndex(input: {
  generationId: string
  mappingRevision?: number
  originalPacketCount: number
  anonymizedPacketCount: number
  droppedBitset?: Uint8Array
  rangeDirectory: readonly SourceRangeEntry[]
}): PcapRecoveryResult<BuildCompactIndexResult> {
  const droppedBitset =
    input.droppedBitset
    ?? new Uint8Array(Math.ceil(Math.max(input.originalPacketCount, 1) / 8))
  const arenas: CompactIndexArenas = {
    entryU32: new Uint32Array(0),
    occurrenceU32: new Uint32Array(0),
    stringBytes: new Uint8Array(0),
    stringOffsets: new Uint32Array(0),
    stringLengths: new Uint16Array(0),
    droppedBitset,
    rankCheckpoints: buildRankCheckpoints(droppedBitset, input.originalPacketCount),
    rangeDirectory: packRangeDirectory(input.rangeDirectory),
  }
  const view: CompactIndexView = {
    generationId: input.generationId,
    mappingRevision: input.mappingRevision ?? 0,
    originalPacketCount: input.originalPacketCount,
    anonymizedPacketCount: input.anonymizedPacketCount,
    entryCount: 0,
    occurrenceCount: 0,
    arenas,
  }
  const plaintext = writeCompactIndex({
    generationId: view.generationId,
    mappingRevision: view.mappingRevision,
    originalPacketCount: view.originalPacketCount,
    anonymizedPacketCount: view.anonymizedPacketCount,
    arenas,
  })
  if (!plaintext.ok) return plaintext
  return recoveryOk({ view, plaintext: plaintext.value })
}
