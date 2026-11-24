/**
 * Bounded unlocked lookup index from compact INDEX plaintext.
 * Under maxUnlockedIndexBytes: hold arenas in memory.
 * Over limit: paged LRU of entry views (same UX, no re-prompt).
 */

import { wipeBytes } from '../../../crypto/wipe'
import { ByteBudgetLru } from '../../preview/byteBudgetLru'
import { RecoveryReader } from '../codec/binaryIO'
import {
  COMPACT_ENTRY_STRIDE,
  COMPACT_OCC_STRIDE,
  RECOVERY_COMPACT_INDEX_MAGIC,
  RECOVERY_COMPACT_INDEX_VERSION,
  compactStringAt,
  entryCategory,
  entryMatchKind,
  parseCompactIndex,
  type CompactIndexView,
} from '../codec/compactIndexCodec'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import type { RecoveryLookupCategory, RecoveryMatchKind } from '../domain/types'
import { buildPacketNumberMap } from './packetNumberMap'

const ENTRIES_PER_PAGE = 1024

export interface LookupEntryView {
  readonly entryIndex: number
  readonly category: RecoveryLookupCategory
  readonly matchKind: RecoveryMatchKind
  readonly anonymizedCanonical: string
  readonly anonymizedWire: string
  readonly originalCanonical: string
  readonly originalWire: string
  readonly occurrenceCount: number
  readonly occStart: number
}

export interface LookupOccurrenceView {
  readonly occurrenceIndex: number
  readonly originalPacketNumber: number
  /** -1 when dropped from anonymized capture. */
  readonly anonymizedPacketNumber: number
  readonly fileOffset: number
  readonly dataOffset: number
  readonly byteOffsetInPacket: number
  readonly byteLength: number
}

export interface UnlockedLookupIndex {
  readonly mode: 'memory' | 'paged'
  readonly entryCount: number
  readonly occurrenceCount: number
  readonly generationId: string
  readonly originalPacketCount: number
  readonly anonymizedPacketCount: number
  lookupExact(anonymizedCanonical: string): readonly number[]
  lookupExactWire(anonymizedWire: string): readonly number[]
  getEntry(entryIndex: number): LookupEntryView | null
  getOccurrences(entryIndex: number): readonly LookupOccurrenceView[]
  /** Entries that appear on the given 1-based anonymized packet number. */
  lookupByAnonymizedPacket(anonymizedPacketNumber: number): readonly number[]
  packetMap: import('./packetNumberMap').PacketNumberMap
  /** Absolute end offset of file header / section context span (0 if unknown). */
  fileHeaderEnd(): number
  /** Packet record/block spans in original packet-number order (1-based index via array). */
  orderedPacketSpans(): readonly { spanStart: number; spanEnd: number }[]
  findSpanCovering(fileOffset: number): { spanStart: number; spanEnd: number } | null
  listRangePieces(): readonly {
    fileOffset: number
    length: number
    dataFrameLocalIndex: number
    spanStart: number
    spanEnd: number
  }[]
  wipe(): void
}

export function buildUnlockedLookupIndex(
  plaintext: Uint8Array,
): PcapRecoveryResult<UnlockedLookupIndex> {
  if (plaintext.byteLength <= PCAP_RECOVERY_LIMITS.maxUnlockedIndexBytes) {
    const parsed = parseCompactIndex(plaintext)
    if (!parsed.ok) return parsed
    return recoveryOk(createMemoryIndex(parsed.value))
  }

  const parsed = parseCompactIndexWithMax(plaintext, PCAP_RECOVERY_LIMITS.maxBundleImportBytes)
  if (!parsed.ok) return parsed
  return recoveryOk(createPagedIndex(parsed.value))
}

function parseCompactIndexWithMax(
  bytes: Uint8Array,
  maxBytes: number,
): PcapRecoveryResult<CompactIndexView> {
  if (bytes.byteLength > maxBytes) {
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

  const entryBytes = r.readBytes(
    entryCount.value * COMPACT_ENTRY_STRIDE * 4,
    entryCount.value * COMPACT_ENTRY_STRIDE * 4,
  )
  if (!entryBytes.ok) return entryBytes
  const occBytes = r.readBytes(
    occCount.value * COMPACT_OCC_STRIDE * 4,
    occCount.value * COMPACT_OCC_STRIDE * 4,
  )
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

function entryViewFrom(view: CompactIndexView, entryIndex: number): LookupEntryView | null {
  if (entryIndex < 0 || entryIndex >= view.entryCount) return null
  const category = entryCategory(view.arenas, entryIndex)
  const matchKind = entryMatchKind(view.arenas, entryIndex)
  if (!category || !matchKind) return null
  const base = entryIndex * COMPACT_ENTRY_STRIDE
  const e = view.arenas.entryU32
  return {
    entryIndex,
    category,
    matchKind,
    anonymizedCanonical: compactStringAt(view.arenas, e[base + 2]!),
    anonymizedWire: compactStringAt(view.arenas, e[base + 3]!),
    originalCanonical: compactStringAt(view.arenas, e[base + 4]!),
    originalWire: compactStringAt(view.arenas, e[base + 5]!),
    occStart: e[base + 6]!,
    occurrenceCount: e[base + 7]!,
  }
}

function buildExactMaps(view: CompactIndexView): {
  canonical: Map<string, number[]>
  wire: Map<string, number[]>
  byAnonPacket: Map<number, number[]>
} {
  const canonical = new Map<string, number[]>()
  const wire = new Map<string, number[]>()
  const byAnonPacket = new Map<number, number[]>()
  for (let i = 0; i < view.entryCount; i++) {
    const ev = entryViewFrom(view, i)
    if (!ev) continue
    const cl = canonical.get(ev.anonymizedCanonical) ?? []
    cl.push(i)
    canonical.set(ev.anonymizedCanonical, cl)
    if (ev.anonymizedWire) {
      const wl = wire.get(ev.anonymizedWire) ?? []
      wl.push(i)
      wire.set(ev.anonymizedWire, wl)
    }
    const occs = occurrenceViews(view, i)
    const seenPn = new Set<number>()
    for (const o of occs) {
      if (o.anonymizedPacketNumber < 0) continue
      if (seenPn.has(o.anonymizedPacketNumber)) continue
      seenPn.add(o.anonymizedPacketNumber)
      const pl = byAnonPacket.get(o.anonymizedPacketNumber) ?? []
      pl.push(i)
      byAnonPacket.set(o.anonymizedPacketNumber, pl)
    }
  }
  return { canonical, wire, byAnonPacket }
}

function occurrenceViews(view: CompactIndexView, entryIndex: number): LookupOccurrenceView[] {
  const ev = entryViewFrom(view, entryIndex)
  if (!ev) return []
  const out: LookupOccurrenceView[] = []
  const occ = view.arenas.occurrenceU32
  for (let i = 0; i < ev.occurrenceCount; i++) {
    const base = (ev.occStart + i) * COMPACT_OCC_STRIDE
    const anonPn = occ[base + 1]!
    out.push({
      occurrenceIndex: i,
      originalPacketNumber: occ[base]!,
      anonymizedPacketNumber: anonPn === 0xffffffff ? -1 : anonPn,
      fileOffset: occ[base + 2]!,
      dataOffset: occ[base + 3]!,
      byteOffsetInPacket: occ[base + 4]!,
      byteLength: occ[base + 5]!,
    })
  }
  return out
}

function rangeHelpers(view: CompactIndexView) {
  const rd = view.arenas.rangeDirectory
  const count = Math.floor(rd.length / 6)

  const listRangePieces = () => {
    const out: Array<{
      fileOffset: number
      length: number
      dataFrameLocalIndex: number
      spanStart: number
      spanEnd: number
    }> = []
    for (let i = 0; i < count; i++) {
      const b = i * 6
      out.push({
        spanStart: rd[b]!,
        spanEnd: rd[b + 1]!,
        fileOffset: rd[b + 2]!,
        length: rd[b + 3]!,
        dataFrameLocalIndex: rd[b + 4]!,
      })
    }
    return out
  }

  const uniqueSpans = () => {
    const map = new Map<string, { spanStart: number; spanEnd: number }>()
    for (let i = 0; i < count; i++) {
      const b = i * 6
      const spanStart = rd[b]!
      const spanEnd = rd[b + 1]!
      map.set(`${spanStart}:${spanEnd}`, { spanStart, spanEnd })
    }
    return [...map.values()].sort((a, b) => a.spanStart - b.spanStart)
  }

  const fileHeaderEnd = () => {
    const spans = uniqueSpans()
    const header = spans.find((s) => s.spanStart === 0)
    return header ? header.spanEnd : 0
  }

  const orderedPacketSpans = () => {
    const headerEnd = fileHeaderEnd()
    return uniqueSpans().filter((s) => s.spanStart >= headerEnd && !(s.spanStart === 0 && s.spanEnd === headerEnd))
  }

  const findSpanCovering = (fileOffset: number) => {
    for (const s of uniqueSpans()) {
      if (fileOffset >= s.spanStart && fileOffset < s.spanEnd) return s
    }
    return null
  }

  return { listRangePieces, fileHeaderEnd, orderedPacketSpans, findSpanCovering }
}

function createMemoryIndex(view: CompactIndexView): UnlockedLookupIndex {
  const maps = buildExactMaps(view)
  const packetMap = buildPacketNumberMap(
    view.arenas,
    view.originalPacketCount,
    view.anonymizedPacketCount,
  )
  const ranges = rangeHelpers(view)
  let wiped = false
  return {
    mode: 'memory',
    entryCount: view.entryCount,
    occurrenceCount: view.occurrenceCount,
    generationId: view.generationId,
    originalPacketCount: view.originalPacketCount,
    anonymizedPacketCount: view.anonymizedPacketCount,
    packetMap,
    lookupExact(anonymizedCanonical: string) {
      if (wiped) return []
      return maps.canonical.get(anonymizedCanonical) ?? []
    },
    lookupExactWire(anonymizedWire: string) {
      if (wiped) return []
      return maps.wire.get(anonymizedWire) ?? []
    },
    getEntry(entryIndex: number) {
      if (wiped) return null
      return entryViewFrom(view, entryIndex)
    },
    getOccurrences(entryIndex: number) {
      if (wiped) return []
      return occurrenceViews(view, entryIndex)
    },
    lookupByAnonymizedPacket(anonymizedPacketNumber: number) {
      if (wiped) return []
      return maps.byAnonPacket.get(anonymizedPacketNumber) ?? []
    },
    fileHeaderEnd: () => (wiped ? 0 : ranges.fileHeaderEnd()),
    orderedPacketSpans: () => (wiped ? [] : ranges.orderedPacketSpans()),
    findSpanCovering: (fileOffset) => (wiped ? null : ranges.findSpanCovering(fileOffset)),
    listRangePieces: () => (wiped ? [] : ranges.listRangePieces()),
    wipe() {
      wiped = true
      maps.canonical.clear()
      maps.wire.clear()
      maps.byAnonPacket.clear()
      wipeBytes(view.arenas.stringBytes)
      view.arenas.entryU32.fill(0)
      view.arenas.occurrenceU32.fill(0)
      view.arenas.rangeDirectory.fill(0)
      wipeBytes(view.arenas.droppedBitset)
    },
  }
}

function createPagedIndex(view: CompactIndexView): UnlockedLookupIndex {
  const maps = buildExactMaps(view)
  const packetMap = buildPacketNumberMap(
    view.arenas,
    view.originalPacketCount,
    view.anonymizedPacketCount,
  )
  const ranges = rangeHelpers(view)
  const pageLru = new ByteBudgetLru<number, LookupEntryView[]>(
    Math.min(PCAP_RECOVERY_LIMITS.maxUnlockedIndexBytes, 16 * 1024 * 1024),
  )
  let wiped = false

  const loadPage = (page: number): LookupEntryView[] => {
    const cached = pageLru.get(page)
    if (cached) return cached
    const start = page * ENTRIES_PER_PAGE
    const end = Math.min(start + ENTRIES_PER_PAGE, view.entryCount)
    const rows: LookupEntryView[] = []
    let bytes = 0
    for (let i = start; i < end; i++) {
      const ev = entryViewFrom(view, i)
      if (!ev) continue
      rows.push(ev)
      bytes += 128 + ev.anonymizedCanonical.length + ev.originalCanonical.length
    }
    pageLru.set(page, rows, Math.max(bytes, 256))
    return rows
  }

  return {
    mode: 'paged',
    entryCount: view.entryCount,
    occurrenceCount: view.occurrenceCount,
    generationId: view.generationId,
    originalPacketCount: view.originalPacketCount,
    anonymizedPacketCount: view.anonymizedPacketCount,
    packetMap,
    lookupExact(anonymizedCanonical: string) {
      if (wiped) return []
      return maps.canonical.get(anonymizedCanonical) ?? []
    },
    lookupExactWire(anonymizedWire: string) {
      if (wiped) return []
      return maps.wire.get(anonymizedWire) ?? []
    },
    getEntry(entryIndex: number) {
      if (wiped) return null
      if (entryIndex < 0 || entryIndex >= view.entryCount) return null
      const page = Math.floor(entryIndex / ENTRIES_PER_PAGE)
      const rows = loadPage(page)
      return rows.find((r) => r.entryIndex === entryIndex) ?? entryViewFrom(view, entryIndex)
    },
    getOccurrences(entryIndex: number) {
      if (wiped) return []
      return occurrenceViews(view, entryIndex)
    },
    lookupByAnonymizedPacket(anonymizedPacketNumber: number) {
      if (wiped) return []
      return maps.byAnonPacket.get(anonymizedPacketNumber) ?? []
    },
    fileHeaderEnd: () => (wiped ? 0 : ranges.fileHeaderEnd()),
    orderedPacketSpans: () => (wiped ? [] : ranges.orderedPacketSpans()),
    findSpanCovering: (fileOffset) => (wiped ? null : ranges.findSpanCovering(fileOffset)),
    listRangePieces: () => (wiped ? [] : ranges.listRangePieces()),
    wipe() {
      wiped = true
      maps.canonical.clear()
      maps.wire.clear()
      maps.byAnonPacket.clear()
      pageLru.clear()
      wipeBytes(view.arenas.stringBytes)
      view.arenas.entryU32.fill(0)
      view.arenas.occurrenceU32.fill(0)
      view.arenas.rangeDirectory.fill(0)
      wipeBytes(view.arenas.droppedBitset)
    },
  }
}
