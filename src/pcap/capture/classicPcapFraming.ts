/**
 * Classic PCAP framing engine — shared async parser (Stage 6).
 * Sync reference adapter uses MemoryAsyncCursor; production uses BlobSliceCursor.
 */

import type { IAsyncCaptureCursor } from './asyncCursor'
import {
  type ClassicPcapHeader,
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
  PCAP_MAGIC_MICRO_LE,
  PCAP_MAGIC_MICRO_BE,
  PCAP_MAGIC_NANO_LE,
  PCAP_MAGIC_NANO_BE,
} from '../domain/types'

const GLOBAL_HEADER_SIZE = 24
const PACKET_HEADER_SIZE = 16

export function probeClassicPcap(magic: number): { endian: Endian; tsResol: TimestampResolution } | null {
  switch (magic) {
    case PCAP_MAGIC_MICRO_LE: return { endian: Endian.Little, tsResol: TimestampResolution.Microseconds }
    case PCAP_MAGIC_MICRO_BE: return { endian: Endian.Big, tsResol: TimestampResolution.Microseconds }
    case PCAP_MAGIC_NANO_LE: return { endian: Endian.Little, tsResol: TimestampResolution.Nanoseconds }
    case PCAP_MAGIC_NANO_BE: return { endian: Endian.Big, tsResol: TimestampResolution.Nanoseconds }
    default: return null
  }
}

export interface ClassicPcapFramingOptions {
  /** When true, payload bytes are read into memory (reference adapter). Otherwise skipped. */
  retainPayload?: boolean
  onPayload?: (descriptor: PacketRecordDescriptor, data: Uint8Array) => void
}

export interface ClassicPcapFramingResult {
  readonly header: ClassicPcapHeader | null
  readonly descriptors: readonly PacketRecordDescriptor[]
  readonly issues: readonly ParseIssue[]
  readonly checkpoints: readonly SparseCheckpoint[]
  readonly totalFileBytes: number
}

export async function parseClassicPcapFraming(
  cursor: IAsyncCaptureCursor,
  options: ClassicPcapFramingOptions = {},
): Promise<ClassicPcapFramingResult> {
  const totalFileBytes = cursor.size

  if (totalFileBytes < GLOBAL_HEADER_SIZE) {
    return {
      header: null,
      descriptors: [],
      issues: [{
        severity: IssueSeverity.Fatal,
        code: 'pcap-too-small',
        message: `File too small (${totalFileBytes} bytes)`,
      }],
      checkpoints: [],
      totalFileBytes,
    }
  }

  let header: ClassicPcapHeader
  try {
    header = await readClassicPcapHeaderAsync(cursor)
  } catch {
    return {
      header: null,
      descriptors: [],
      issues: [{
        severity: IssueSeverity.Fatal,
        code: 'pcap-invalid-header',
        message: 'Failed to parse PCAP global header',
      }],
      checkpoints: [],
      totalFileBytes,
    }
  }

  const le = header.endian === Endian.Little
  const unitsPerSecond = header.timestampResolution === TimestampResolution.Nanoseconds
    ? 1_000_000_000n
    : 1_000_000n
  const offsetSeconds = BigInt(header.tzOffset)

  const descriptors: PacketRecordDescriptor[] = []
  const issues: ParseIssue[] = []
  const checkpoints: SparseCheckpoint[] = []
  let packetNumber = 0

  while (cursor.remaining() >= PACKET_HEADER_SIZE) {
    const recordOffset = cursor.offset
    const tsSec = le ? await cursor.u32le() : await cursor.u32be()
    const tsFrac = le ? await cursor.u32le() : await cursor.u32be()
    const inclLen = le ? await cursor.u32le() : await cursor.u32be()
    const origLen = le ? await cursor.u32le() : await cursor.u32be()
    const dataOffset = cursor.offset

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

    if (cursor.remaining() < inclLen) {
      issues.push({
        severity: IssueSeverity.Error,
        code: 'pcap-truncated',
        message: `Packet ${packetNumber} truncated: need ${inclLen} bytes, have ${cursor.remaining()}`,
        packetNumber,
        fileOffset: recordOffset,
      })
      break
    }

    const ticks = BigInt(tsSec) * unitsPerSecond + BigInt(tsFrac)
    const timestamp: PacketTimestamp = { ticks, unitsPerSecond, offsetSeconds }

    const descriptor: PacketRecordDescriptor = {
      packetNumber,
      timestamp,
      capturedLength: inclLen,
      originalLength: origLen,
      linkType: header.linkType,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: recordOffset,
      dataOffset,
    }

    if (options.retainPayload && options.onPayload) {
      const data = await cursor.slice(inclLen)
      options.onPayload(descriptor, data)
    } else if (options.retainPayload) {
      await cursor.slice(inclLen)
    } else {
      await cursor.skip(inclLen)
    }

    descriptors.push(descriptor)

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

  return { header, descriptors, issues, checkpoints, totalFileBytes }
}

async function readClassicPcapHeaderAsync(cursor: IAsyncCaptureCursor): Promise<ClassicPcapHeader> {
  const magic = await cursor.u32le()
  const probe = probeClassicPcap(magic)
  if (!probe) {
    throw new Error(`Not a classic PCAP file (magic: 0x${magic.toString(16)})`)
  }
  const { endian, tsResol } = probe
  const le = endian === Endian.Little

  const versionMajor = le ? await cursor.u16le() : await cursor.u16be()
  const versionMinor = le ? await cursor.u16le() : await cursor.u16be()
  const tzOffset = le ? await cursor.i32le() : await cursor.i32be()
  const sigfigs = le ? await cursor.u32le() : await cursor.u32be()
  const snapLen = le ? await cursor.u32le() : await cursor.u32be()
  const linkType = le ? await cursor.u32le() : await cursor.u32be()

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

export { GLOBAL_HEADER_SIZE, PACKET_HEADER_SIZE }
