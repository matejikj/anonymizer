/**
 * RecoveryIndexSeedPort — compact transferable seed from processing/mapping.
 *
 * Seed contains anonymized values + span refs only (no original plaintext).
 * Export worker hydrates originals from sourceBlob by span and builds INDEX frames.
 */

import type { PacketRecordDescriptor } from '../../domain/types'
import type { PcapPlanSnapshot } from '../../export/planSnapshot'
import type { MappingSnapshot } from '../../../mapping/types'
import type { PacketDiscoveryResult, TransformationIntent } from '../../discovery/types'
import { mappingKey } from '../../../mapping/types'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import type { RecoveryLookupCategory, RecoveryMatchKind } from '../domain/types'
import { categoryId, matchKindId, toRecoveryLookupCategory } from '../codec/categoryIds'
import { RecoveryReader, RecoveryWriter } from '../codec/binaryIO'

export const RECOVERY_INDEX_SEED_MAGIC = 'RCSEED01'
export const RECOVERY_INDEX_SEED_VERSION = 1

/** One occurrence reference in the seed (no original bytes). */
export interface RecoveryIndexSeedOccurrenceInput {
  readonly originalPacketNumber: number
  /** -1 when dropped from anonymized capture. */
  readonly anonymizedPacketNumber: number
  readonly fileOffset: number
  readonly dataOffset: number
  readonly byteOffsetInPacket: number
  readonly byteLength: number
  readonly protocolId: number
  readonly fieldId: number
}

export interface RecoveryIndexSeedEntryInput {
  readonly category: RecoveryLookupCategory
  readonly matchKind: RecoveryMatchKind
  readonly anonymizedCanonical: string
  readonly anonymizedWire: string
  readonly occurrences: readonly RecoveryIndexSeedOccurrenceInput[]
}

export interface RecoveryIndexSeedBuildInput {
  readonly generationId: string
  readonly mappingRevision: number
  readonly originalPacketCount: number
  readonly anonymizedPacketCount: number
  /** Bit i set ⇒ original packetNumber (1-based) i+? — we use 0-based packet index. */
  readonly droppedPacketIndexes: readonly number[]
  readonly entries: readonly RecoveryIndexSeedEntryInput[]
}

export interface ParsedRecoveryIndexSeed {
  readonly generationId: string
  readonly mappingRevision: number
  readonly originalPacketCount: number
  readonly anonymizedPacketCount: number
  readonly droppedBitset: Uint8Array
  readonly entryCount: number
  readonly occurrenceCount: number
  /** Packed arenas — no per-occurrence JS objects. */
  readonly arenas: RecoveryIndexSeedArenas
}

/**
 * Typed-array arenas for the seed. Consumers must not rehydrate to object graphs
 * on the UI thread.
 */
export interface RecoveryIndexSeedArenas {
  /** Per entry: categoryId, matchKind, anonCanStr, anonWireStr, occStart, occCount, protocolId, fieldId */
  readonly entryU32: Uint32Array
  readonly occurrenceU32: Uint32Array
  readonly stringBytes: Uint8Array
  readonly stringOffsets: Uint32Array
  readonly stringLengths: Uint16Array
}

const ENTRY_STRIDE = 8
const OCC_STRIDE = 8

export function buildPacketNumberMap(plan: PcapPlanSnapshot): {
  originalToAnonymized: Int32Array
  anonymizedPacketCount: number
  droppedIndexes: number[]
} {
  const maxPn = plan.packets.reduce((m, p) => Math.max(m, p.packetNumber), 0)
  const map = new Int32Array(Math.max(maxPn + 1, plan.packets.length + 1))
  map.fill(-1)
  const droppedIndexes: number[] = []
  let anon = 0
  for (const pkt of plan.packets) {
    if (pkt.drop) {
      droppedIndexes.push(pkt.index)
      map[pkt.packetNumber] = -1
    } else {
      anon += 1
      map[pkt.packetNumber] = anon
    }
  }
  return { originalToAnonymized: map, anonymizedPacketCount: anon, droppedIndexes }
}

export function collectRecoveryIntents(
  packetDiscovery: readonly PacketDiscoveryResult[],
): TransformationIntent[] {
  const out: TransformationIntent[] = []
  for (const packet of packetDiscovery) {
    for (const intent of packet.intents) out.push(intent)
  }
  return out
}

/**
 * Build seed from discovery intents + mapping snapshot + plan.
 * Packs immediately into binary — callers should transfer the ArrayBuffer and drop inputs.
 */
export function buildRecoveryIndexSeedFromDiscovery(input: {
  generationId: string
  mappingRevision: number
  intents: readonly TransformationIntent[]
  snapshot: MappingSnapshot
  plan: PcapPlanSnapshot
  descriptors: readonly PacketRecordDescriptor[]
}): PcapRecoveryResult<ArrayBuffer> {
  const aliasByKey = new Map<string, { alias: string; disposition: string }>()
  for (const e of input.snapshot.entries) {
    aliasByKey.set(mappingKey(e.category, e.canonical), {
      alias: e.alias,
      disposition: e.disposition,
    })
  }

  const descByIndex = new Map<number, PacketRecordDescriptor>()
  for (const d of input.descriptors) {
    // descriptors are keyed by packet number in many paths; also try index match via plan
    descByIndex.set(d.packetNumber, d)
  }
  for (const pkt of input.plan.packets) {
    const d = input.descriptors.find((x) => x.packetNumber === pkt.packetNumber)
    if (d) descByIndex.set(pkt.index, d)
  }

  const { originalToAnonymized, anonymizedPacketCount, droppedIndexes } = buildPacketNumberMap(input.plan)

  type Acc = {
    category: RecoveryLookupCategory
    matchKind: RecoveryMatchKind
    anonymizedCanonical: string
    anonymizedWire: string
    occurrences: RecoveryIndexSeedOccurrenceInput[]
  }
  const byKey = new Map<string, Acc>()

  for (const intent of input.intents) {
    if (intent.kind === 'entity-replacement') {
      const category = toRecoveryLookupCategory(intent.category)
      const mapped = aliasByKey.get(mappingKey(intent.category, intent.canonical))
      const anonymizedCanonical = mapped?.alias ?? intent.canonical
      const matchKind: RecoveryMatchKind =
        mapped?.disposition === 'ambiguous-fixed' ? 'ambiguous' : 'exact'
      const key = `${category}\0${anonymizedCanonical}`
      let acc = byKey.get(key)
      if (!acc) {
        acc = {
          category,
          matchKind,
          anonymizedCanonical,
          anonymizedWire: anonymizedCanonical,
          occurrences: [],
        }
        byKey.set(key, acc)
      } else if (matchKind === 'ambiguous') {
        acc.matchKind = 'ambiguous'
      }
      const desc =
        descByIndex.get(intent.packetIndex)
        ?? input.descriptors.find((d) => d.packetNumber === intent.packetIndex + 1)
      const planPkt = input.plan.packets[intent.packetIndex]
      const originalPacketNumber = planPkt?.packetNumber ?? intent.packetIndex + 1
      const anonymizedPacketNumber = originalToAnonymized[originalPacketNumber] ?? -1
      acc.occurrences.push({
        originalPacketNumber,
        anonymizedPacketNumber,
        fileOffset: desc?.fileOffset ?? 0,
        dataOffset: desc?.dataOffset ?? 0,
        byteOffsetInPacket: intent.offset,
        byteLength: intent.byteLength,
        protocolId: 0,
        fieldId: 0,
      })
    } else if (intent.kind === 'fixed-redaction' || intent.kind === 'mask-range') {
      const anonymizedCanonical = intent.kind === 'mask-range' ? `mask:${intent.reason}` : '********'
      const key = `redacted\0${anonymizedCanonical}\0${intent.byteLength}`
      let acc = byKey.get(key)
      if (!acc) {
        acc = {
          category: 'other',
          matchKind: 'redacted',
          anonymizedCanonical,
          anonymizedWire: anonymizedCanonical,
          occurrences: [],
        }
        byKey.set(key, acc)
      } else {
        acc.matchKind = 'ambiguous'
      }
      const desc =
        descByIndex.get(intent.packetIndex)
        ?? input.descriptors.find((d) => d.packetNumber === intent.packetIndex + 1)
      const planPkt = input.plan.packets[intent.packetIndex]
      const originalPacketNumber = planPkt?.packetNumber ?? intent.packetIndex + 1
      acc.occurrences.push({
        originalPacketNumber,
        anonymizedPacketNumber: originalToAnonymized[originalPacketNumber] ?? -1,
        fileOffset: desc?.fileOffset ?? 0,
        dataOffset: desc?.dataOffset ?? 0,
        byteOffsetInPacket: intent.offset,
        byteLength: intent.byteLength,
        protocolId: 0,
        fieldId: 0,
      })
    }
  }

  // Shared anonymized masks with >1 distinct original canonicals stay ambiguous.
  const anonCount = new Map<string, number>()
  for (const acc of byKey.values()) {
    if (acc.matchKind === 'exact') {
      const n = (anonCount.get(acc.anonymizedCanonical) ?? 0) + 1
      anonCount.set(acc.anonymizedCanonical, n)
    }
  }
  for (const acc of byKey.values()) {
    if ((anonCount.get(acc.anonymizedCanonical) ?? 0) > 1) {
      acc.matchKind = 'ambiguous'
    }
  }

  return serializeRecoveryIndexSeed({
    generationId: input.generationId,
    mappingRevision: input.mappingRevision,
    originalPacketCount: input.plan.packets.length,
    anonymizedPacketCount,
    droppedPacketIndexes: droppedIndexes,
    entries: [...byKey.values()],
  })
}

export function serializeRecoveryIndexSeed(
  input: RecoveryIndexSeedBuildInput,
): PcapRecoveryResult<ArrayBuffer> {
  if (input.entries.length > PCAP_RECOVERY_LIMITS.maxLookupEntries) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many lookup entries')
  }
  let occurrenceCount = 0
  for (const e of input.entries) occurrenceCount += e.occurrences.length
  if (occurrenceCount > PCAP_RECOVERY_LIMITS.maxOccurrences) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many occurrences')
  }

  const stringTable = new Map<string, number>()
  const strings: string[] = []
  const intern = (s: string): number => {
    const existing = stringTable.get(s)
    if (existing !== undefined) return existing
    const id = strings.length
    stringTable.set(s, id)
    strings.push(s)
    return id
  }

  const entryU32 = new Uint32Array(input.entries.length * ENTRY_STRIDE)
  const occurrenceU32 = new Uint32Array(occurrenceCount * OCC_STRIDE)
  let occWrite = 0
  let entryWrite = 0

  for (const e of input.entries) {
    const occStart = occWrite
    for (const o of e.occurrences) {
      const base = occWrite * OCC_STRIDE
      occurrenceU32[base] = o.originalPacketNumber >>> 0
      occurrenceU32[base + 1] = o.anonymizedPacketNumber < 0 ? 0xffffffff : o.anonymizedPacketNumber >>> 0
      occurrenceU32[base + 2] = o.fileOffset >>> 0
      occurrenceU32[base + 3] = o.dataOffset >>> 0
      occurrenceU32[base + 4] = o.byteOffsetInPacket >>> 0
      occurrenceU32[base + 5] = o.byteLength >>> 0
      occurrenceU32[base + 6] = o.protocolId >>> 0
      occurrenceU32[base + 7] = o.fieldId >>> 0
      occWrite += 1
    }
    const base = entryWrite * ENTRY_STRIDE
    entryU32[base] = categoryId(e.category)
    entryU32[base + 1] = matchKindId(e.matchKind)
    entryU32[base + 2] = intern(e.anonymizedCanonical)
    entryU32[base + 3] = intern(e.anonymizedWire)
    entryU32[base + 4] = occStart
    entryU32[base + 5] = e.occurrences.length
    entryU32[base + 6] = e.occurrences[0]?.protocolId ?? 0
    entryU32[base + 7] = e.occurrences[0]?.fieldId ?? 0
    entryWrite += 1
  }

  const bitset = new Uint8Array(Math.ceil(input.originalPacketCount / 8))
  for (const idx of input.droppedPacketIndexes) {
    if (idx < 0 || idx >= input.originalPacketCount) continue
    bitset[idx >> 3]! |= 1 << (idx & 7)
  }

  const w = new RecoveryWriter()
  const magic = new TextEncoder().encode(RECOVERY_INDEX_SEED_MAGIC)
  w.writeBytes(magic)
  w.writeU16(RECOVERY_INDEX_SEED_VERSION)
  const genBytes = new TextEncoder().encode(input.generationId)
  if (genBytes.byteLength > 256) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'generationId too long')
  }
  w.writeU16(genBytes.byteLength)
  w.writeBytes(genBytes)
  w.writeU32(input.mappingRevision)
  w.writeU32(input.originalPacketCount)
  w.writeU32(input.anonymizedPacketCount)
  w.writeU32(input.entries.length)
  w.writeU32(occurrenceCount)
  w.writeU32(strings.length)
  w.writeU32(bitset.byteLength)
  w.writeBytes(bitset)

  for (const s of strings) {
    const b = new TextEncoder().encode(s)
    if (b.byteLength > PCAP_RECOVERY_LIMITS.maxStringBytes) {
      return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'string exceeds limit')
    }
    w.writeU16(b.byteLength)
    w.writeBytes(b)
  }

  w.writeBytes(new Uint8Array(entryU32.buffer, entryU32.byteOffset, entryU32.byteLength))
  w.writeBytes(new Uint8Array(occurrenceU32.buffer, occurrenceU32.byteOffset, occurrenceU32.byteLength))

  const bytes = w.toUint8Array()
  if (bytes.byteLength > PCAP_RECOVERY_LIMITS.maxUnlockedIndexBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'index seed exceeds limit')
  }
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return recoveryOk(copy.buffer)
}

export function parseRecoveryIndexSeed(buffer: ArrayBuffer): PcapRecoveryResult<ParsedRecoveryIndexSeed> {
  const bytes = new Uint8Array(buffer)
  if (bytes.byteLength > PCAP_RECOVERY_LIMITS.maxUnlockedIndexBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'index seed exceeds limit')
  }
  const r = new RecoveryReader(bytes)
  const magic = r.readBytes(8, 8)
  if (!magic.ok) return magic
  if (new TextDecoder().decode(magic.value) !== RECOVERY_INDEX_SEED_MAGIC) {
    return recoveryFail(PCAP_RECOVERY_ERROR.indexInvalid, 'invalid seed magic')
  }
  const version = r.readU16()
  if (!version.ok) return version
  if (version.value !== RECOVERY_INDEX_SEED_VERSION) {
    return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, 'unsupported seed version')
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
  const occurrenceCount = r.readU32()
  if (!occurrenceCount.ok) return occurrenceCount
  const stringCount = r.readU32()
  if (!stringCount.ok) return stringCount
  const bitsetLen = r.readU32()
  if (!bitsetLen.ok) return bitsetLen
  if (entryCount.value > PCAP_RECOVERY_LIMITS.maxLookupEntries) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many lookup entries')
  }
  if (occurrenceCount.value > PCAP_RECOVERY_LIMITS.maxOccurrences) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many occurrences')
  }
  const droppedBitset = r.readBytes(bitsetLen.value, Math.ceil(originalPacketCount.value / 8) + 64)
  if (!droppedBitset.ok) return droppedBitset

  const stringOffsets = new Uint32Array(stringCount.value)
  const stringLengths = new Uint16Array(stringCount.value)
  const stringChunks: Uint8Array[] = []
  let stringTotal = 0
  for (let i = 0; i < stringCount.value; i++) {
    const len = r.readU16()
    if (!len.ok) return len
    if (len.value > PCAP_RECOVERY_LIMITS.maxStringBytes) {
      return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'string exceeds limit')
    }
    const s = r.readBytes(len.value, PCAP_RECOVERY_LIMITS.maxStringBytes)
    if (!s.ok) return s
    stringOffsets[i] = stringTotal
    stringLengths[i] = len.value
    stringChunks.push(s.value)
    stringTotal += len.value
  }
  const stringBytes = new Uint8Array(stringTotal)
  for (let i = 0; i < stringChunks.length; i++) {
    stringBytes.set(stringChunks[i]!, stringOffsets[i]!)
  }

  const entryBytes = r.readBytes(entryCount.value * ENTRY_STRIDE * 4, entryCount.value * ENTRY_STRIDE * 4)
  if (!entryBytes.ok) return entryBytes
  const occBytes = r.readBytes(occurrenceCount.value * OCC_STRIDE * 4, occurrenceCount.value * OCC_STRIDE * 4)
  if (!occBytes.ok) return occBytes
  const consumed = r.expectConsumed()
  if (!consumed.ok) return consumed

  const entryU32 = new Uint32Array(
    entryBytes.value.buffer.slice(
      entryBytes.value.byteOffset,
      entryBytes.value.byteOffset + entryBytes.value.byteLength,
    ),
  )
  const occurrenceU32 = new Uint32Array(
    occBytes.value.buffer.slice(
      occBytes.value.byteOffset,
      occBytes.value.byteOffset + occBytes.value.byteLength,
    ),
  )

  return recoveryOk({
    generationId: generationId.value,
    mappingRevision: mappingRevision.value,
    originalPacketCount: originalPacketCount.value,
    anonymizedPacketCount: anonymizedPacketCount.value,
    droppedBitset: droppedBitset.value,
    entryCount: entryCount.value,
    occurrenceCount: occurrenceCount.value,
    arenas: {
      entryU32,
      occurrenceU32,
      stringBytes,
      stringOffsets,
      stringLengths,
    },
  })
}

export function seedStringAt(arenas: RecoveryIndexSeedArenas, id: number): string {
  const off = arenas.stringOffsets[id]!
  const len = arenas.stringLengths[id]!
  return new TextDecoder().decode(arenas.stringBytes.subarray(off, off + len))
}

export { ENTRY_STRIDE as SEED_ENTRY_STRIDE, OCC_STRIDE as SEED_OCC_STRIDE }
