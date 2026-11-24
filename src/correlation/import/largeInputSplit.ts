/**
 * T73 — split oversized text/PCAP inputs into correlation segments within per-file limits.
 * Aggregate bytes remain the session budget (ADR-5); export merges segments into one file (D7).
 * PCAP segments carry a trailing overlap so TCP reassembly can see flows across the cut.
 */

import {
  BYTES_PER_MIB,
  CORRELATION_SESSION_LIMITS,
  MAX_PCAP_FILE_BYTES,
  MAX_TEXT_FILE_BYTES,
} from '../../domain/capabilityContract.ts'
import { SourceKind as SK } from '../../domain/sourceArtifact.ts'
import {
  CaptureFormat,
  Endian,
  PCAP_MAGIC_MICRO_BE,
  PCAP_MAGIC_MICRO_LE,
  PCAP_MAGIC_NANO_BE,
  PCAP_MAGIC_NANO_LE,
  PCAPNG_BYTE_ORDER_MAGIC,
} from '../../pcap/domain/types.ts'
import { probeFormat } from '../../pcap/capture/probe.ts'

const CLASSIC_GLOBAL_HEADER = 24
const CLASSIC_PACKET_HEADER = 16
const BT_SHB = 0x0a0d0d0a
const BT_EPB = 0x00000006
const BT_SPB = 0x00000003
const BT_PB = 0x00000002

export const LARGE_INPUT_SPLIT = {
  textMaxSegmentBytes: MAX_TEXT_FILE_BYTES,
  pcapMaxSegmentBytes: MAX_PCAP_FILE_BYTES,
  /** Bytes of prior packets repeated at the start of the next PCAP segment (reassembly). */
  pcapOverlapBytes: 4 * BYTES_PER_MIB,
  maxSegments: CORRELATION_SESSION_LIMITS.maxSources,
  maxAggregateBytes: CORRELATION_SESSION_LIMITS.maxAggregateBytes,
} as const

export type LargeInputSplitFormat = 'text' | 'classic-pcap' | 'pcapng'

export interface LargeInputSegment {
  readonly file: File
  readonly index: number
  readonly count: number
  /**
   * Byte offset in this segment file where content unique to this segment begins
   * (after global/section preamble and any overlap). Length-preserving export keeps this layout.
   */
  readonly uniquePayloadStart: number
  readonly format: LargeInputSplitFormat
}

export interface LargeInputSplitOk {
  readonly ok: true
  readonly kind: typeof SK.Text | typeof SK.Pcap
  readonly format: LargeInputSplitFormat
  readonly splitGroupId: string
  readonly mergeOutputBaseName: string
  readonly segments: readonly LargeInputSegment[]
  /** Sum of segment file sizes (includes overlap duplication). */
  readonly aggregateBytes: number
}

export interface LargeInputSplitFail {
  readonly ok: false
  readonly code: 'aggregate-too-large' | 'split-failed' | 'too-many-segments' | 'empty'
  readonly message: string
}

export type LargeInputSplitResult = LargeInputSplitOk | LargeInputSplitFail

export function needsLargeInputSplit(
  byteLength: number,
  kind: typeof SK.Text | typeof SK.Pcap,
): boolean {
  const cap = kind === SK.Pcap ? LARGE_INPUT_SPLIT.pcapMaxSegmentBytes : LARGE_INPUT_SPLIT.textMaxSegmentBytes
  return byteLength > cap
}

function newSplitGroupId(): string {
  return `split-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}

function mergeBaseName(fileName: string, kind: typeof SK.Text | typeof SK.Pcap): string {
  if (kind === SK.Pcap) {
    return fileName.replace(/\.(pcap|pcapng|cap)$/i, '') || 'capture'
  }
  return fileName.replace(/\.(log|txt)$/i, '') || 'log'
}

function segmentFileName(base: string, index: number, count: number, kind: typeof SK.Text | typeof SK.Pcap, format: LargeInputSplitFormat): string {
  const pad = String(index + 1).padStart(String(count).length, '0')
  if (kind === SK.Pcap) {
    const ext = format === 'pcapng' ? 'pcapng' : 'pcap'
    return `${base}.part${pad}.${ext}`
  }
  return `${base}.part${pad}.log`
}

function fileFromBytes(bytes: Uint8Array, name: string, lastModified: number): File {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return new File([copy], name, { type: 'application/octet-stream', lastModified })
}

interface PacketSpan {
  readonly start: number
  readonly end: number
}

function classicEndian(magic: number): Endian | null {
  if (magic === PCAP_MAGIC_MICRO_LE || magic === PCAP_MAGIC_NANO_LE) return Endian.Little
  if (magic === PCAP_MAGIC_MICRO_BE || magic === PCAP_MAGIC_NANO_BE) return Endian.Big
  return null
}

function walkClassicPackets(bytes: Uint8Array): PacketSpan[] | null {
  if (bytes.byteLength < CLASSIC_GLOBAL_HEADER) return null
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const magic = view.getUint32(0, true)
  const endian = classicEndian(magic) ?? classicEndian(view.getUint32(0, false))
  if (endian === null) return null
  const le = endian === Endian.Little
  const spans: PacketSpan[] = []
  let offset = CLASSIC_GLOBAL_HEADER
  while (offset + CLASSIC_PACKET_HEADER <= bytes.byteLength) {
    const inclLen = view.getUint32(offset + 8, le)
    const recordEnd = offset + CLASSIC_PACKET_HEADER + inclLen
    if (inclLen > LARGE_INPUT_SPLIT.pcapMaxSegmentBytes || recordEnd > bytes.byteLength) {
      return null
    }
    spans.push({ start: offset, end: recordEnd })
    offset = recordEnd
  }
  return spans
}

function packPacketIndexRanges(
  spans: readonly PacketSpan[],
  preambleBytes: number,
  maxSeg: number,
  overlapBytes: number,
): { from: number; to: number; uniqueFrom: number }[] | null {
  if (spans.length === 0) return null

  const ranges: { from: number; to: number; uniqueFrom: number }[] = []
  let i = 0
  let nextUniqueFrom: number | null = null

  while (i < spans.length) {
    const uniqueFrom = nextUniqueFrom ?? i
    let end = i
    let body = 0
    while (end < spans.length) {
      const nextLen = spans[end]!.end - spans[end]!.start
      if (preambleBytes + body + nextLen > maxSeg && end > i) break
      if (preambleBytes + nextLen > maxSeg) return null
      body += nextLen
      end += 1
    }
    if (end <= i) return null
    ranges.push({ from: i, to: end, uniqueFrom: Math.max(uniqueFrom, i) })
    if (end >= spans.length) break

    let overlap = 0
    let start = end
    for (let j = end - 1; j >= 0; j--) {
      const len = spans[j]!.end - spans[j]!.start
      if (overlap > 0 && overlap + len > overlapBytes) break
      overlap += len
      start = j
      if (overlap >= overlapBytes) break
    }
    nextUniqueFrom = end
    if (start <= i && start < end) {
      // Could not rewind for overlap — advance without overlap.
      i = end
      nextUniqueFrom = end
    } else {
      i = start
    }
  }
  return ranges
}

function buildClassicSegmentFiles(
  bytes: Uint8Array,
  spans: readonly PacketSpan[],
  ranges: readonly { from: number; to: number; uniqueFrom: number }[],
  base: string,
  lastModified: number,
): LargeInputSegment[] {
  const header = bytes.subarray(0, CLASSIC_GLOBAL_HEADER)
  const count = ranges.length
  const out: LargeInputSegment[] = []
  for (let ri = 0; ri < ranges.length; ri++) {
    const r = ranges[ri]!
    let size = CLASSIC_GLOBAL_HEADER
    for (let p = r.from; p < r.to; p++) size += spans[p]!.end - spans[p]!.start
    const buf = new Uint8Array(size)
    buf.set(header, 0)
    let o = CLASSIC_GLOBAL_HEADER
    for (let p = r.from; p < r.to; p++) {
      const sp = spans[p]!
      buf.set(bytes.subarray(sp.start, sp.end), o)
      o += sp.end - sp.start
    }
    let uniquePayloadStart = CLASSIC_GLOBAL_HEADER
    for (let p = r.from; p < r.uniqueFrom; p++) {
      uniquePayloadStart += spans[p]!.end - spans[p]!.start
    }
    const name = segmentFileName(base, ri, count, SK.Pcap, 'classic-pcap')
    out.push({
      file: fileFromBytes(buf, name, lastModified),
      index: ri,
      count,
      uniquePayloadStart,
      format: 'classic-pcap',
    })
  }
  return out
}

interface NgBlock {
  readonly start: number
  readonly end: number
  readonly type: number
  readonly isPacket: boolean
}

function walkPcapngBlocks(bytes: Uint8Array): { blocks: NgBlock[]; le: boolean } | null {
  if (bytes.byteLength < 12) return null
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const type0 = view.getUint32(0, true)
  if (type0 !== BT_SHB && view.getUint32(0, false) !== BT_SHB) return null

  // BOM in SHB decides endian
  let le = true
  const totalLen0 = view.getUint32(4, true)
  if (bytes.byteLength >= 16) {
    const bomLe = view.getUint32(8, true)
    const bomBe = view.getUint32(8, false)
    if (bomLe === PCAPNG_BYTE_ORDER_MAGIC) le = true
    else if (bomBe === PCAPNG_BYTE_ORDER_MAGIC) le = false
    else if (type0 === BT_SHB) le = true
    else le = false
  }
  void totalLen0

  const blocks: NgBlock[] = []
  let offset = 0
  while (offset + 12 <= bytes.byteLength) {
    const type = view.getUint32(offset, le)
    const totalLen = view.getUint32(offset + 4, le)
    if (totalLen < 12 || (totalLen & 3) !== 0 || offset + totalLen > bytes.byteLength) {
      return null
    }
    const isPacket = type === BT_EPB || type === BT_SPB || type === BT_PB
    blocks.push({ start: offset, end: offset + totalLen, type, isPacket })
    offset += totalLen
  }
  return { blocks, le }
}

function splitPcapng(
  bytes: Uint8Array,
  maxSeg: number,
  overlapBytes: number,
  base: string,
  lastModified: number,
): LargeInputSegment[] | null {
  const walked = walkPcapngBlocks(bytes)
  if (!walked) return null
  const { blocks } = walked

  // Preamble = leading SHB + consecutive IDBs (and non-packet until first packet)
  let preambleEnd = 0
  for (const b of blocks) {
    if (b.isPacket) break
    preambleEnd = b.end
  }
  const preamble = bytes.subarray(0, preambleEnd)
  const packets = blocks.filter((b) => b.isPacket)
  if (packets.length === 0) return null

  const spans: PacketSpan[] = packets.map((p) => ({ start: p.start, end: p.end }))
  const ranges = packPacketIndexRanges(spans, preamble.byteLength, maxSeg, overlapBytes)
  if (!ranges) return null

  const count = ranges.length
  const out: LargeInputSegment[] = []
  for (let ri = 0; ri < ranges.length; ri++) {
    const r = ranges[ri]!
    let size = preamble.byteLength
    for (let p = r.from; p < r.to; p++) size += spans[p]!.end - spans[p]!.start
    const buf = new Uint8Array(size)
    buf.set(preamble, 0)
    let o = preamble.byteLength
    for (let p = r.from; p < r.to; p++) {
      const sp = spans[p]!
      buf.set(bytes.subarray(sp.start, sp.end), o)
      o += sp.end - sp.start
    }
    let uniquePayloadStart = preamble.byteLength
    for (let p = r.from; p < r.uniqueFrom; p++) {
      uniquePayloadStart += spans[p]!.end - spans[p]!.start
    }
    out.push({
      file: fileFromBytes(buf, segmentFileName(base, ri, count, SK.Pcap, 'pcapng'), lastModified),
      index: ri,
      count,
      uniquePayloadStart,
      format: 'pcapng',
    })
  }
  return out
}

function splitText(
  bytes: Uint8Array,
  maxSeg: number,
  base: string,
  lastModified: number,
): LargeInputSegment[] | null {
  if (bytes.byteLength === 0) return null
  const cuts: number[] = [0]
  let segStart = 0
  let i = 0
  while (i < bytes.byteLength) {
    const remaining = bytes.byteLength - segStart
    if (remaining <= maxSeg) break
    const limit = segStart + maxSeg
    // Prefer last LF/CR before limit
    let cut = -1
    for (let j = limit; j > segStart; j--) {
      const b = bytes[j - 1]!
      if (b === 0x0a || b === 0x0d) {
        cut = j
        break
      }
    }
    if (cut <= segStart) {
      // No line break — hard cut at maxSeg (oversized line)
      cut = limit
    }
    cuts.push(cut)
    segStart = cut
    i = cut
  }
  cuts.push(bytes.byteLength)
  if (cuts.length - 1 > LARGE_INPUT_SPLIT.maxSegments) return null

  const count = cuts.length - 1
  const out: LargeInputSegment[] = []
  for (let s = 0; s < count; s++) {
    const start = cuts[s]!
    const end = cuts[s + 1]!
    out.push({
      file: fileFromBytes(bytes.subarray(start, end), segmentFileName(base, s, count, SK.Text, 'text'), lastModified),
      index: s,
      count,
      uniquePayloadStart: 0,
      format: 'text',
    })
  }
  return out
}

/**
 * Split a file that exceeds the per-kind byte cap into correlation-ready segments.
 * Caller must only invoke when {@link needsLargeInputSplit} is true.
 */
export async function splitLargeInput(
  file: File,
  kind: typeof SK.Text | typeof SK.Pcap,
  options: { readonly signal?: AbortSignal } = {},
): Promise<LargeInputSplitResult> {
  if (options.signal?.aborted) {
    return { ok: false, code: 'split-failed', message: 'cancelled' }
  }
  if (file.size <= 0) {
    return { ok: false, code: 'empty', message: 'empty' }
  }

  // Reject before materializing when even a perfect split cannot fit the aggregate.
  if (file.size > LARGE_INPUT_SPLIT.maxAggregateBytes) {
    return {
      ok: false,
      code: 'aggregate-too-large',
      message: 'aggregate',
    }
  }

  const bytes = new Uint8Array(await file.arrayBuffer())
  if (options.signal?.aborted) {
    return { ok: false, code: 'split-failed', message: 'cancelled' }
  }

  const base = mergeBaseName(file.name, kind)
  let segments: LargeInputSegment[] | null = null
  let format: LargeInputSplitFormat = 'text'

  if (kind === SK.Text) {
    format = 'text'
    segments = splitText(bytes, LARGE_INPUT_SPLIT.textMaxSegmentBytes, base, file.lastModified)
  } else {
    const head = bytes.subarray(0, Math.min(8, bytes.byteLength))
    const probed = probeFormat(head.buffer.slice(head.byteOffset, head.byteOffset + head.byteLength) as ArrayBuffer)
    if (probed.format === CaptureFormat.ClassicPcap) {
      format = 'classic-pcap'
      const spans = walkClassicPackets(bytes)
      if (!spans || spans.length === 0) {
        return { ok: false, code: 'split-failed', message: 'pcap-walk' }
      }
      const ranges = packPacketIndexRanges(
        spans,
        CLASSIC_GLOBAL_HEADER,
        LARGE_INPUT_SPLIT.pcapMaxSegmentBytes,
        LARGE_INPUT_SPLIT.pcapOverlapBytes,
      )
      if (!ranges) {
        return { ok: false, code: 'split-failed', message: 'pcap-pack' }
      }
      segments = buildClassicSegmentFiles(bytes, spans, ranges, base, file.lastModified)
    } else if (probed.format === CaptureFormat.Pcapng) {
      format = 'pcapng'
      segments = splitPcapng(
        bytes,
        LARGE_INPUT_SPLIT.pcapMaxSegmentBytes,
        LARGE_INPUT_SPLIT.pcapOverlapBytes,
        base,
        file.lastModified,
      )
    } else {
      return { ok: false, code: 'split-failed', message: 'unknown-pcap' }
    }
  }

  if (!segments || segments.length === 0) {
    return { ok: false, code: 'split-failed', message: 'empty-segments' }
  }
  if (segments.length > LARGE_INPUT_SPLIT.maxSegments) {
    return { ok: false, code: 'too-many-segments', message: 'too-many' }
  }

  let aggregateBytes = 0
  for (const s of segments) aggregateBytes += s.file.size
  if (aggregateBytes > LARGE_INPUT_SPLIT.maxAggregateBytes) {
    return { ok: false, code: 'aggregate-too-large', message: 'aggregate' }
  }

  return {
    ok: true,
    kind,
    format,
    splitGroupId: newSplitGroupId(),
    mergeOutputBaseName: base,
    segments,
    aggregateBytes,
  }
}

/** Concatenate anonymized segment exports into one file (D7). */
export function mergeSplitExportBytes(
  parts: readonly { readonly bytes: Uint8Array; readonly uniquePayloadStart: number }[],
): Uint8Array {
  if (parts.length === 0) return new Uint8Array(0)
  if (parts.length === 1) return parts[0]!.bytes

  let total = parts[0]!.bytes.byteLength
  for (let i = 1; i < parts.length; i++) {
    const p = parts[i]!
    const start = Math.min(p.uniquePayloadStart, p.bytes.byteLength)
    total += p.bytes.byteLength - start
  }
  const out = new Uint8Array(total)
  out.set(parts[0]!.bytes, 0)
  let o = parts[0]!.bytes.byteLength
  for (let i = 1; i < parts.length; i++) {
    const p = parts[i]!
    const start = Math.min(p.uniquePayloadStart, p.bytes.byteLength)
    out.set(p.bytes.subarray(start), o)
    o += p.bytes.byteLength - start
  }
  return out
}
