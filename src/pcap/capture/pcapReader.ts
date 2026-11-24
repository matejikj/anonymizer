/**
 * Classic PCAP reference adapter (sync BoundedCursor) + async framing wrappers.
 */

import { BoundedCursor } from './BoundedCursor'
import {
  type ClassicPcapHeader,
  type PacketEnvelope,
  type PacketRecordDescriptor,
  type PacketTimestamp,
  type ParseIssue,
  type SparseCheckpoint,
  CaptureFormat,
  Endian,
  IssueSeverity,
  MAX_PACKET_COUNT,
  MAX_RECORD_SIZE,
  SPARSE_CHECKPOINT_INTERVAL,
  TimestampResolution,
} from '../domain/types'
import { MemoryAsyncCursor, BlobSliceCursor } from './asyncCursor'
import {
  parseClassicPcapFraming,
  probeClassicPcap,
  GLOBAL_HEADER_SIZE,
  PACKET_HEADER_SIZE,
  type ClassicPcapFramingResult,
} from './classicPcapFraming'
import { hydratePayloads } from './packetHydration'

export { hydratePayloads } from './packetHydration'

export function readClassicPcapHeader(cursor: BoundedCursor): ClassicPcapHeader {
  const magic = cursor.u32le()
  const probe = probeClassicPcap(magic)
  if (!probe) {
    throw new Error(`Not a classic PCAP file (magic: 0x${magic.toString(16)})`)
  }
  const { endian, tsResol } = probe
  const le = endian === Endian.Little

  const versionMajor = le ? cursor.u16le() : cursor.u16be()
  const versionMinor = le ? cursor.u16le() : cursor.u16be()
  const tzOffset = le ? cursor.i32le() : cursor.i32be()
  const sigfigs = le ? cursor.u32le() : cursor.u32be()
  const snapLen = le ? cursor.u32le() : cursor.u32be()
  const linkType = le ? cursor.u32le() : cursor.u32be()

  return {
    format: CaptureFormat.ClassicPcap,
    endian,
    timestampResolution: tsResol,
    versionMajor,
    versionMinor,
    snapLen,
    linkType: linkType & 0x0000ffff,
    tzOffset,
    sigfigs,
  }
}

export interface ClassicPcapReadResult extends ClassicPcapFramingResult {
  readonly packets: readonly PacketEnvelope[]
}

/** Sync reference adapter over BoundedCursor (tests / parity baseline). */
export function readClassicPcap(buffer: ArrayBuffer): ClassicPcapReadResult {
  const framed = readClassicPcapFromBounded(buffer)
  const descriptors = packetsToDescriptors(framed.packets)
  return { ...framed, descriptors, packets: framed.packets }
}

function readClassicPcapFromBounded(buffer: ArrayBuffer): Omit<ClassicPcapReadResult, 'descriptors'> {
  if (buffer.byteLength < GLOBAL_HEADER_SIZE) {
    return {
      header: null,
      packets: [],
      issues: [{ severity: IssueSeverity.Fatal, code: 'pcap-too-small', message: `File too small (${buffer.byteLength} bytes)` }],
      checkpoints: [],
      totalFileBytes: buffer.byteLength,
    }
  }

  const cursor = new BoundedCursor(buffer)
  let header: ClassicPcapHeader
  try {
    header = readClassicPcapHeader(cursor)
  } catch {
    return {
      header: null,
      packets: [],
      issues: [{ severity: IssueSeverity.Fatal, code: 'pcap-invalid-header', message: 'Failed to parse PCAP global header' }],
      checkpoints: [],
      totalFileBytes: buffer.byteLength,
    }
  }
  const le = header.endian === Endian.Little
  const unitsPerSecond = header.timestampResolution === TimestampResolution.Nanoseconds
    ? 1_000_000_000n
    : 1_000_000n
  const offsetSeconds = BigInt(header.tzOffset)

  const packets: PacketEnvelope[] = []
  const issues: ParseIssue[] = []
  const checkpoints: SparseCheckpoint[] = []
  let packetNumber = 0

  while (cursor.remaining >= PACKET_HEADER_SIZE) {
    const recordOffset = cursor.offset
    const tsSec = le ? cursor.u32le() : cursor.u32be()
    const tsFrac = le ? cursor.u32le() : cursor.u32be()
    const inclLen = le ? cursor.u32le() : cursor.u32be()
    const origLen = le ? cursor.u32le() : cursor.u32be()

    if (inclLen > MAX_RECORD_SIZE) {
      issues.push({
        severity: IssueSeverity.Fatal,
        code: 'pcap-record-too-large',
        message: `Packet ${packetNumber} captured length ${inclLen} exceeds ${MAX_RECORD_SIZE}`,
        packetNumber,
        fileOffset: recordOffset,
      })
      break
    }

    if (inclLen > origLen) {
      issues.push({
        severity: IssueSeverity.Warning,
        code: 'pcap-incl-gt-orig',
        message: `Packet ${packetNumber}: incl_len ${inclLen} > orig_len ${origLen}`,
        packetNumber,
        fileOffset: recordOffset,
      })
    }

    if (cursor.remaining < inclLen) {
      issues.push({
        severity: IssueSeverity.Error,
        code: 'pcap-truncated',
        message: `Packet ${packetNumber} truncated: need ${inclLen} bytes, have ${cursor.remaining}`,
        packetNumber,
        fileOffset: recordOffset,
      })
      break
    }

    const data = cursor.slice(inclLen)
    const ticks = BigInt(tsSec) * unitsPerSecond + BigInt(tsFrac)
    const timestamp: PacketTimestamp = { ticks, unitsPerSecond, offsetSeconds }

    packets.push({
      packetNumber,
      timestamp,
      capturedLength: inclLen,
      originalLength: origLen,
      linkType: header.linkType,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: recordOffset,
      data,
    })

    if (packetNumber % SPARSE_CHECKPOINT_INTERVAL === 0) {
      checkpoints.push({ packetNumber, fileOffset: recordOffset })
    }

    packetNumber++
    if (packetNumber > MAX_PACKET_COUNT) {
      issues.push({
        severity: IssueSeverity.Fatal,
        code: 'pcap-too-many-packets',
        message: `Exceeded maximum packet count ${MAX_PACKET_COUNT}`,
        packetNumber,
      })
      break
    }
  }

  return { header, packets, issues, checkpoints, totalFileBytes: buffer.byteLength }
}

/** Async framing via shared engine (MemoryAsyncCursor). */
export async function readClassicPcapFramed(buffer: ArrayBuffer): Promise<ClassicPcapReadResult> {
  const payloads = new Map<number, Uint8Array>()
  const framed = await parseClassicPcapFraming(new MemoryAsyncCursor(buffer), {
    retainPayload: true,
    onPayload: (d, data) => payloads.set(d.packetNumber, data),
  })
  return framingToReadResult(framed, payloads)
}

/** Incremental production parse from Blob (no whole-file ArrayBuffer). */
export async function readClassicPcapFromBlob(blob: Blob): Promise<ClassicPcapReadResult> {
  const framed = await parseClassicPcapFraming(new BlobSliceCursor(blob), { retainPayload: false })
  const payloads = await hydratePayloads(blob, framed.descriptors)
  return framingToReadResult(framed, payloads)
}

function framingToReadResult(
  framed: ClassicPcapFramingResult,
  payloads: Map<number, Uint8Array>,
): ClassicPcapReadResult {
  const packets: PacketEnvelope[] = framed.descriptors.map((d) => ({
    packetNumber: d.packetNumber,
    timestamp: d.timestamp,
    capturedLength: d.capturedLength,
    originalLength: d.originalLength,
    linkType: d.linkType,
    interfaceId: d.interfaceId,
    sectionIndex: d.sectionIndex,
    fileOffset: d.fileOffset,
    data: payloads.get(d.packetNumber) ?? new Uint8Array(0),
  }))
  return { ...framed, packets }
}

function packetsToDescriptors(packets: readonly PacketEnvelope[]): PacketRecordDescriptor[] {
  return packets.map((p) => ({
    packetNumber: p.packetNumber,
    timestamp: p.timestamp,
    capturedLength: p.capturedLength,
    originalLength: p.originalLength,
    linkType: p.linkType,
    interfaceId: p.interfaceId,
    sectionIndex: p.sectionIndex,
    fileOffset: p.fileOffset,
    dataOffset: p.fileOffset + PACKET_HEADER_SIZE,
  }))
}

export { probeClassicPcap, GLOBAL_HEADER_SIZE, PACKET_HEADER_SIZE } from './classicPcapFraming'
