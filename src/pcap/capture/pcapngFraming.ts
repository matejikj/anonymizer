/**
 * PCAPNG framing engine — shared async parser (Stage 6).
 * Sync reference adapter uses MemoryAsyncCursor; production uses BlobSliceCursor.
 */

import type { IAsyncCaptureCursor } from './asyncCursor'
import {
  type PacketRecordDescriptor,
  type PacketTimestamp,
  type ParseIssue,
  type PcapngInterfaceInfo,
  type PcapngSectionInfo,
  type SparseCheckpoint,
  Endian,
  IssueSeverity,
  MAX_PACKET_COUNT,
  MAX_RECORD_SIZE,
  SPARSE_CHECKPOINT_INTERVAL,
  TimestampResolution,
  PCAPNG_BYTE_ORDER_MAGIC,
} from '../domain/types'
import {
  classifyPcapngBlock,
  isDsbBlock,
  isNrbBlock,
} from './pcapngPolicy'

const BT_SHB = 0x0a0d0d0a
const BT_IDB = 0x00000001
const BT_EPB = 0x00000006
const BT_SPB = 0x00000003
const BT_OPB = 0x00000002
const BT_NRB = 0x00000004
const BT_ISB = 0x00000005
const BT_DSB = 0x0000000a

const OPT_ENDOFOPT = 0
const OPT_IF_TSRESOL = 9
const OPT_IF_TSOFFSET = 14

export interface PcapngFramingOptions {
  /** When true, payload bytes are read into memory (reference adapter). Otherwise skipped. */
  retainPayload?: boolean
  onPayload?: (descriptor: PacketRecordDescriptor, data: Uint8Array) => void
}

export interface PcapngFramingResult {
  readonly sections: readonly PcapngSectionInfo[]
  readonly interfaces: readonly PcapngInterfaceInfo[]
  readonly descriptors: readonly PacketRecordDescriptor[]
  readonly issues: readonly ParseIssue[]
  readonly checkpoints: readonly SparseCheckpoint[]
  readonly droppedMetadataBlocks: number
  /** Decryption Secrets Block count dropped on ingest (always ≥0; must be 0 in export). */
  readonly droppedDsbBlocks: number
  readonly droppedNrbBlocks: number
  readonly totalFileBytes: number
}

export async function parsePcapngFraming(
  cursor: IAsyncCaptureCursor,
  options: PcapngFramingOptions = {},
): Promise<PcapngFramingResult> {
  const sections: PcapngSectionInfo[] = []
  const interfaces: PcapngInterfaceInfo[] = []
  const descriptors: PacketRecordDescriptor[] = []
  const issues: ParseIssue[] = []
  const checkpoints: SparseCheckpoint[] = []
  let droppedMetadataBlocks = 0
  let droppedDsbBlocks = 0
  let droppedNrbBlocks = 0
  let packetNumber = 0

  let currentEndian: Endian = Endian.Little
  let sectionIndex = -1
  let sectionInterfaceStart = 0

  const totalFileBytes = cursor.size

  while (cursor.remaining() >= 12) {
    const blockFileOffset = cursor.offset
    const blockType = await cursor.u32le()

    if (blockType === BT_SHB) {
      const totalLen = await cursor.u32le()
      const bom = await cursor.u32le()

      if (bom === PCAPNG_BYTE_ORDER_MAGIC) {
        currentEndian = Endian.Little
      } else if (bom === 0x4d3c2b1a) {
        currentEndian = Endian.Big
      } else {
        issues.push({
          severity: IssueSeverity.Fatal,
          code: 'pcapng-bad-bom',
          message: `Invalid byte order magic 0x${bom.toString(16)} at offset ${blockFileOffset}`,
          fileOffset: blockFileOffset,
        })
        break
      }

      const le = currentEndian === Endian.Little
      const realTotalLen = le ? totalLen : swapU32(totalLen)

      if (cursor.remaining() < 12) {
        issues.push({
          severity: IssueSeverity.Fatal,
          code: 'pcapng-truncated-shb',
          message: `SHB truncated before version/section-length fields at offset ${blockFileOffset}`,
          fileOffset: blockFileOffset,
        })
        break
      }

      const vMajor = le ? await cursor.u16le() : await cursor.u16be()
      const vMinor = le ? await cursor.u16le() : await cursor.u16be()
      const sectionLength = le ? await cursor.u64le() : await cursor.u64be()

      sectionIndex++
      sectionInterfaceStart = interfaces.length

      sections.push({
        sectionIndex,
        endian: currentEndian,
        versionMajor: vMajor,
        versionMinor: vMinor,
        sectionLength: sectionLength === 0xffffffffffffffffn ? -1n : sectionLength,
      })

      const consumed = 24
      const remaining = realTotalLen - consumed - 4
      if (remaining > 0 && remaining <= cursor.remaining()) {
        await cursor.skip(remaining)
      }
      if (cursor.remaining() >= 4) {
        await cursor.skip(4)
      }
      continue
    }

    const le = currentEndian === Endian.Little
    const realBlockType = le ? blockType : swapU32(blockType)
    const totalLen = le ? await cursor.u32le() : await cursor.u32be()

    if (totalLen < 12 || totalLen % 4 !== 0) {
      issues.push({
        severity: IssueSeverity.Error,
        code: 'pcapng-bad-block-length',
        message: `Block at ${blockFileOffset}: total_length ${totalLen} invalid`,
        fileOffset: blockFileOffset,
      })
      break
    }

    if (totalLen > MAX_RECORD_SIZE) {
      issues.push({
        severity: IssueSeverity.Fatal,
        code: 'pcapng-block-too-large',
        message: `Block at ${blockFileOffset}: total_length ${totalLen} exceeds ${MAX_RECORD_SIZE}`,
        fileOffset: blockFileOffset,
      })
      break
    }

    const bodyLen = totalLen - 12
    if (cursor.remaining() < bodyLen + 4) {
      issues.push({
        severity: IssueSeverity.Error,
        code: 'pcapng-truncated-block',
        message: `Block at ${blockFileOffset} truncated`,
        fileOffset: blockFileOffset,
      })
      break
    }

    const bodyStart = cursor.offset

    switch (realBlockType) {
      case BT_IDB:
        await readIDB(cursor, le, sectionIndex, interfaces, sectionInterfaceStart)
        break

      case BT_EPB:
        await readEPB(
          cursor, le, sectionIndex, sectionInterfaceStart, interfaces,
          descriptors, issues, checkpoints, blockFileOffset, packetNumber, options,
        )
        packetNumber++
        break

      case BT_SPB:
        await readSPB(
          cursor, le, sectionIndex, sectionInterfaceStart, interfaces,
          descriptors, issues, checkpoints, blockFileOffset, packetNumber, bodyLen, options,
        )
        packetNumber++
        break

      case BT_OPB:
        await readOPB(
          cursor, le, sectionIndex, sectionInterfaceStart, interfaces,
          descriptors, issues, checkpoints, blockFileOffset, packetNumber, options,
        )
        packetNumber++
        break

      case BT_NRB:
      case BT_ISB:
      case BT_DSB:
        droppedMetadataBlocks++
        if (isDsbBlock(blockType)) droppedDsbBlocks++
        if (isNrbBlock(blockType)) droppedNrbBlocks++
        break

      default:
        // Unknown / custom — drop (allowlist deny-by-default)
        if (classifyPcapngBlock(blockType) !== 'keep') {
          droppedMetadataBlocks++
        }
        break
    }

    await cursor.seek(bodyStart + bodyLen)
    const trailingLen = le ? await cursor.u32le() : await cursor.u32be()
    if (trailingLen !== totalLen) {
      issues.push({
        severity: IssueSeverity.Warning,
        code: 'pcapng-trailing-length-mismatch',
        message: `Block at ${blockFileOffset}: trailing length ${trailingLen} != ${totalLen}`,
        fileOffset: blockFileOffset,
      })
    }

    if (packetNumber > MAX_PACKET_COUNT) {
      issues.push({
        severity: IssueSeverity.Fatal,
        code: 'pcapng-too-many-packets',
        message: `Exceeded maximum packet count ${MAX_PACKET_COUNT}`,
        packetNumber,
      })
      break
    }
  }

  return {
    sections,
    interfaces,
    descriptors,
    issues,
    checkpoints,
    droppedMetadataBlocks,
    droppedDsbBlocks,
    droppedNrbBlocks,
    totalFileBytes,
  }
}

async function readIDB(
  cursor: IAsyncCaptureCursor,
  le: boolean,
  sectionIndex: number,
  interfaces: PcapngInterfaceInfo[],
  sectionInterfaceStart: number,
): Promise<void> {
  const linkType = le ? await cursor.u16le() : await cursor.u16be()
  await cursor.skip(2)
  const snapLen = le ? await cursor.u32le() : await cursor.u32be()

  let tsResol: TimestampResolution = TimestampResolution.Microseconds
  let tsResolValue = 6
  let tsOffset = 0n

  try {
    while (cursor.remaining() >= 4) {
      const optCode = le ? await cursor.u16le() : await cursor.u16be()
      const optLen = le ? await cursor.u16le() : await cursor.u16be()
      if (optCode === OPT_ENDOFOPT) break
      const padded = (optLen + 3) & ~3
      if (cursor.remaining() < padded) break

      if (optCode === OPT_IF_TSRESOL && optLen === 1) {
        const val = await cursor.u8()
        tsResolValue = val
        if (val & 0x80) {
          tsResol = TimestampResolution.Nanoseconds
        } else {
          tsResol = val === 9 ? TimestampResolution.Nanoseconds : TimestampResolution.Microseconds
        }
        await cursor.skip(padded - 1)
      } else if (optCode === OPT_IF_TSOFFSET && optLen === 8) {
        tsOffset = le ? await cursor.u64le() : await cursor.u64be()
      } else {
        await cursor.skip(padded)
      }
    }
  } catch {
    // Options parsing is best-effort
  }

  interfaces.push({
    interfaceId: interfaces.length - sectionInterfaceStart,
    sectionIndex,
    linkType,
    snapLen,
    tsResol,
    tsResolValue,
    tsOffset,
  })
}

function makeTimestampFromHiLo(tsHigh: number, tsLow: number, iface: PcapngInterfaceInfo): PacketTimestamp {
  const rawTs = (BigInt(tsHigh) << 32n) | BigInt(tsLow >>> 0)
  const tsResolVal = iface.tsResolValue
  let unitsPerSecond: bigint
  if (tsResolVal & 0x80) {
    unitsPerSecond = 1n << BigInt(tsResolVal & 0x7f)
  } else {
    unitsPerSecond = 10n ** BigInt(tsResolVal)
  }
  return { ticks: rawTs, unitsPerSecond, offsetSeconds: iface.tsOffset }
}

async function readEPB(
  cursor: IAsyncCaptureCursor,
  le: boolean,
  sectionIndex: number,
  sectionInterfaceStart: number,
  interfaces: PcapngInterfaceInfo[],
  descriptors: PacketRecordDescriptor[],
  issues: ParseIssue[],
  checkpoints: SparseCheckpoint[],
  blockFileOffset: number,
  packetNumber: number,
  options: PcapngFramingOptions,
): Promise<void> {
  const ifaceId = le ? await cursor.u32le() : await cursor.u32be()
  const tsHigh = le ? await cursor.u32le() : await cursor.u32be()
  const tsLow = le ? await cursor.u32le() : await cursor.u32be()
  const capturedLen = le ? await cursor.u32le() : await cursor.u32be()
  const originalLen = le ? await cursor.u32le() : await cursor.u32be()

  const globalIfaceIdx = sectionInterfaceStart + ifaceId
  const iface = interfaces[globalIfaceIdx]
  if (!iface) {
    issues.push({
      severity: IssueSeverity.Error,
      code: 'pcapng-unknown-interface',
      message: `EPB packet ${packetNumber} references undefined interface ${ifaceId}`,
      packetNumber,
      fileOffset: blockFileOffset,
    })
    return
  }

  if (capturedLen > MAX_RECORD_SIZE) {
    issues.push({
      severity: IssueSeverity.Fatal,
      code: 'pcapng-block-too-large',
      message: `EPB packet ${packetNumber} captured length ${capturedLen} exceeds ${MAX_RECORD_SIZE}`,
      packetNumber,
      fileOffset: blockFileOffset,
    })
    return
  }

  if (capturedLen > cursor.remaining()) {
    issues.push({
      severity: IssueSeverity.Error,
      code: 'pcapng-epb-truncated',
      message: `EPB packet ${packetNumber} data truncated`,
      packetNumber,
      fileOffset: blockFileOffset,
    })
    return
  }

  const dataOffset = cursor.offset
  const timestamp = makeTimestampFromHiLo(tsHigh, tsLow, iface)

  const descriptor: PacketRecordDescriptor = {
    packetNumber,
    timestamp,
    capturedLength: capturedLen,
    originalLength: originalLen,
    linkType: iface.linkType,
    interfaceId: ifaceId,
    sectionIndex,
    fileOffset: blockFileOffset,
    dataOffset,
  }

  if (options.retainPayload && options.onPayload) {
    const data = await cursor.slice(capturedLen)
    options.onPayload(descriptor, data)
  } else if (options.retainPayload) {
    await cursor.slice(capturedLen)
  } else {
    await cursor.skip(capturedLen)
  }

  descriptors.push(descriptor)

  if (packetNumber % SPARSE_CHECKPOINT_INTERVAL === 0) {
    checkpoints.push({ packetNumber, fileOffset: blockFileOffset })
  }
}

async function readSPB(
  cursor: IAsyncCaptureCursor,
  le: boolean,
  sectionIndex: number,
  sectionInterfaceStart: number,
  interfaces: PcapngInterfaceInfo[],
  descriptors: PacketRecordDescriptor[],
  issues: ParseIssue[],
  checkpoints: SparseCheckpoint[],
  blockFileOffset: number,
  packetNumber: number,
  bodyLen: number,
  options: PcapngFramingOptions,
): Promise<void> {
  const originalLen = le ? await cursor.u32le() : await cursor.u32be()
  const iface = interfaces[sectionInterfaceStart]
  if (!iface) {
    issues.push({
      severity: IssueSeverity.Error,
      code: 'pcapng-spb-no-interface',
      message: `SPB packet ${packetNumber}: no interface defined`,
      packetNumber,
      fileOffset: blockFileOffset,
    })
    return
  }

  const capturedLen = Math.min(originalLen, iface.snapLen, bodyLen - 4)
  if (capturedLen > MAX_RECORD_SIZE) {
    issues.push({
      severity: IssueSeverity.Fatal,
      code: 'pcapng-block-too-large',
      message: `SPB packet ${packetNumber} captured length ${capturedLen} exceeds ${MAX_RECORD_SIZE}`,
      packetNumber,
      fileOffset: blockFileOffset,
    })
    return
  }

  if (capturedLen > cursor.remaining()) return

  const dataOffset = cursor.offset
  const timestamp: PacketTimestamp = { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n }

  const descriptor: PacketRecordDescriptor = {
    packetNumber,
    timestamp,
    capturedLength: capturedLen,
    originalLength: originalLen,
    linkType: iface.linkType,
    interfaceId: 0,
    sectionIndex,
    fileOffset: blockFileOffset,
    dataOffset,
  }

  if (options.retainPayload && options.onPayload) {
    const data = await cursor.slice(capturedLen)
    options.onPayload(descriptor, data)
  } else if (options.retainPayload) {
    await cursor.slice(capturedLen)
  } else {
    await cursor.skip(capturedLen)
  }

  descriptors.push(descriptor)

  if (packetNumber % SPARSE_CHECKPOINT_INTERVAL === 0) {
    checkpoints.push({ packetNumber, fileOffset: blockFileOffset })
  }
}

async function readOPB(
  cursor: IAsyncCaptureCursor,
  le: boolean,
  sectionIndex: number,
  sectionInterfaceStart: number,
  interfaces: PcapngInterfaceInfo[],
  descriptors: PacketRecordDescriptor[],
  issues: ParseIssue[],
  checkpoints: SparseCheckpoint[],
  blockFileOffset: number,
  packetNumber: number,
  options: PcapngFramingOptions,
): Promise<void> {
  const ifaceId = le ? await cursor.u16le() : await cursor.u16be()
  await cursor.skip(2)
  const tsHigh = le ? await cursor.u32le() : await cursor.u32be()
  const tsLow = le ? await cursor.u32le() : await cursor.u32be()
  const capturedLen = le ? await cursor.u32le() : await cursor.u32be()
  const originalLen = le ? await cursor.u32le() : await cursor.u32be()

  const globalIfaceIdx = sectionInterfaceStart + ifaceId
  const iface = interfaces[globalIfaceIdx]
  if (!iface) {
    issues.push({
      severity: IssueSeverity.Error,
      code: 'pcapng-unknown-interface',
      message: `OPB packet ${packetNumber} references undefined interface ${ifaceId}`,
      packetNumber,
      fileOffset: blockFileOffset,
    })
    return
  }

  if (capturedLen > MAX_RECORD_SIZE) {
    issues.push({
      severity: IssueSeverity.Fatal,
      code: 'pcapng-block-too-large',
      message: `OPB packet ${packetNumber} captured length ${capturedLen} exceeds ${MAX_RECORD_SIZE}`,
      packetNumber,
      fileOffset: blockFileOffset,
    })
    return
  }

  if (capturedLen > cursor.remaining()) return

  const dataOffset = cursor.offset
  const timestamp = makeTimestampFromHiLo(tsHigh, tsLow, iface)

  const descriptor: PacketRecordDescriptor = {
    packetNumber,
    timestamp,
    capturedLength: capturedLen,
    originalLength: originalLen,
    linkType: iface.linkType,
    interfaceId: ifaceId,
    sectionIndex,
    fileOffset: blockFileOffset,
    dataOffset,
  }

  if (options.retainPayload && options.onPayload) {
    const data = await cursor.slice(capturedLen)
    options.onPayload(descriptor, data)
  } else if (options.retainPayload) {
    await cursor.slice(capturedLen)
  } else {
    await cursor.skip(capturedLen)
  }

  descriptors.push(descriptor)

  if (packetNumber % SPARSE_CHECKPOINT_INTERVAL === 0) {
    checkpoints.push({ packetNumber, fileOffset: blockFileOffset })
  }
}

function swapU32(v: number): number {
  return (
    ((v & 0xff) << 24) |
    ((v & 0xff00) << 8) |
    ((v & 0xff0000) >>> 8) |
    ((v & 0xff000000) >>> 24)
  ) >>> 0
}
