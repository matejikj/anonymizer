/**
 * PCAPNG reference adapter (sync BoundedCursor) + async framing wrappers.
 */

import { BoundedCursor } from './BoundedCursor';
import { MemoryAsyncCursor, BlobSliceCursor } from './asyncCursor';
import { hydratePayloads } from './packetHydration';
import {
  parsePcapngFraming,
  type PcapngFramingResult,
} from './pcapngFraming';
import {
  type PacketEnvelope,
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
} from '../domain/types';
import {
  classifyPcapngBlock,
  isDsbBlock,
  isNrbBlock,
} from './pcapngPolicy';

export { hydratePayloads } from './packetHydration';

// Block type constants
const BT_SHB = 0x0a0d0d0a;
const BT_IDB = 0x00000001;
const BT_EPB = 0x00000006;
const BT_SPB = 0x00000003;
const BT_OPB = 0x00000002; // obsolete Packet Block
const BT_NRB = 0x00000004;
const BT_ISB = 0x00000005;
const BT_DSB = 0x0000000a;

// Option codes
const OPT_ENDOFOPT = 0;
const OPT_IF_TSRESOL = 9;
const OPT_IF_TSOFFSET = 14;

export interface PcapngReadResult extends PcapngFramingResult {
  readonly packets: readonly PacketEnvelope[];
}

/** Sync reference adapter over BoundedCursor (tests / parity baseline). */
export function readPcapng(buffer: ArrayBuffer): PcapngReadResult {
  return readPcapngFromBounded(buffer);
}

function readPcapngFromBounded(buffer: ArrayBuffer): PcapngReadResult {
  const cursor = new BoundedCursor(buffer);
  const sections: PcapngSectionInfo[] = [];
  const interfaces: PcapngInterfaceInfo[] = [];
  const packets: PacketEnvelope[] = [];
  const descriptors: PacketRecordDescriptor[] = [];
  const issues: ParseIssue[] = [];
  const checkpoints: SparseCheckpoint[] = [];
  let droppedMetadataBlocks = 0;
  let droppedDsbBlocks = 0;
  let droppedNrbBlocks = 0;
  let packetNumber = 0;

  let currentEndian: Endian = Endian.Little;
  let sectionIndex = -1;
  // interfaces local to current section
  let sectionInterfaceStart = 0;

  while (cursor.remaining >= 12) {
    const blockFileOffset = cursor.offset;
    const blockType = cursor.u32le(); // always read type as LE initially

    if (blockType === BT_SHB) {
      // SHB: determine endian from byte order magic
      const totalLen = cursor.u32le(); // provisional
      const bom = cursor.u32le();

      if (bom === PCAPNG_BYTE_ORDER_MAGIC) {
        currentEndian = Endian.Little;
      } else if (bom === 0x4d3c2b1a) {
        currentEndian = Endian.Big;
      } else {
        issues.push({
          severity: IssueSeverity.Fatal,
          code: 'pcapng-bad-bom',
          message: `Invalid byte order magic 0x${bom.toString(16)} at offset ${blockFileOffset}`,
          fileOffset: blockFileOffset,
        });
        break;
      }

      // Re-read total length in correct endian if needed
      const le = currentEndian === Endian.Little;
      // totalLen was read as LE; if BE, re-interpret
      const realTotalLen = le ? totalLen : swapU32(totalLen);

      // vMajor(2) + vMinor(2) + sectionLength(8) = 12 more bytes. The outer loop only
      // guarantees 12 bytes on entry (type+len+bom already consumed those), so a file
      // truncated right after a valid BOM would otherwise throw BoundsError here instead
      // of failing closed like every other malformed-input case in this reader.
      if (cursor.remaining < 12) {
        issues.push({
          severity: IssueSeverity.Fatal,
          code: 'pcapng-truncated-shb',
          message: `SHB truncated before version/section-length fields at offset ${blockFileOffset}`,
          fileOffset: blockFileOffset,
        });
        break;
      }

      const vMajor = le ? cursor.u16le() : cursor.u16be();
      const vMinor = le ? cursor.u16le() : cursor.u16be();
      const sectionLength = le ? cursor.u64le() : cursor.u64be();

      sectionIndex++;
      sectionInterfaceStart = interfaces.length;

      sections.push({
        sectionIndex,
        endian: currentEndian,
        versionMajor: vMajor,
        versionMinor: vMinor,
        sectionLength: sectionLength === 0xffffffffffffffffn ? -1n : sectionLength,
      });

      // skip rest of SHB (options + trailing length)
      const consumed = 24; // type(4) + len(4) + bom(4) + ver(4) + seclen(8) - already at offset 24 from block start
      const remaining = realTotalLen - consumed - 4; // -4 for trailing total_length
      if (remaining > 0 && remaining <= cursor.remaining) {
        cursor.skip(remaining);
      }
      // read trailing total length
      if (cursor.remaining >= 4) {
        cursor.skip(4);
      }
      continue;
    }

    // For all other blocks, re-read type in correct endian if needed
    const le = currentEndian === Endian.Little;
    const realBlockType = le ? blockType : swapU32(blockType);

    // total_length is next — but we already consumed 4 bytes for blockType
    // Actually cursor already advanced past blockType. Read totalLen.
    const totalLen = le ? cursor.u32le() : cursor.u32be();

    if (totalLen < 12 || totalLen % 4 !== 0) {
      issues.push({
        severity: IssueSeverity.Error,
        code: 'pcapng-bad-block-length',
        message: `Block at ${blockFileOffset}: total_length ${totalLen} invalid`,
        fileOffset: blockFileOffset,
      });
      break;
    }

    if (totalLen > MAX_RECORD_SIZE) {
      issues.push({
        severity: IssueSeverity.Fatal,
        code: 'pcapng-block-too-large',
        message: `Block at ${blockFileOffset}: total_length ${totalLen} exceeds ${MAX_RECORD_SIZE}`,
        fileOffset: blockFileOffset,
      });
      break;
    }

    // body length = totalLen - 12 (type + len + trailing len)
    const bodyLen = totalLen - 12;
    if (cursor.remaining < bodyLen + 4) {
      issues.push({
        severity: IssueSeverity.Error,
        code: 'pcapng-truncated-block',
        message: `Block at ${blockFileOffset} truncated`,
        fileOffset: blockFileOffset,
      });
      break;
    }

    const bodyStart = cursor.offset;

    switch (realBlockType) {
      case BT_IDB:
        readIDB(cursor, le, sectionIndex, interfaces, sectionInterfaceStart);
        break;

      case BT_EPB:
        readEPB(cursor, le, sectionIndex, sectionInterfaceStart, interfaces, packets, descriptors, issues, checkpoints, blockFileOffset, packetNumber);
        packetNumber++;
        break;

      case BT_SPB:
        readSPB(cursor, le, sectionIndex, sectionInterfaceStart, interfaces, packets, descriptors, issues, checkpoints, blockFileOffset, packetNumber, bodyLen);
        packetNumber++;
        break;

      case BT_OPB:
        readOPB(cursor, le, sectionIndex, sectionInterfaceStart, interfaces, packets, descriptors, issues, checkpoints, blockFileOffset, packetNumber);
        packetNumber++;
        break;

      case BT_NRB:
      case BT_ISB:
      case BT_DSB:
        droppedMetadataBlocks++;
        if (isDsbBlock(blockType)) droppedDsbBlocks++;
        if (isNrbBlock(blockType)) droppedNrbBlocks++;
        break;

      default:
        if (classifyPcapngBlock(blockType) !== 'keep') {
          droppedMetadataBlocks++;
        }
        break;
    }

    // Seek to end of block body + trailing total_length
    cursor.seek(bodyStart + bodyLen);
    const trailingLen = le ? cursor.u32le() : cursor.u32be();
    if (trailingLen !== totalLen) {
      issues.push({
        severity: IssueSeverity.Warning,
        code: 'pcapng-trailing-length-mismatch',
        message: `Block at ${blockFileOffset}: trailing length ${trailingLen} != ${totalLen}`,
        fileOffset: blockFileOffset,
      });
    }

    if (packetNumber > MAX_PACKET_COUNT) {
      issues.push({
        severity: IssueSeverity.Fatal,
        code: 'pcapng-too-many-packets',
        message: `Exceeded maximum packet count ${MAX_PACKET_COUNT}`,
        packetNumber,
      });
      break;
    }
  }

  return { sections, interfaces, descriptors, packets, issues, checkpoints, droppedMetadataBlocks, droppedDsbBlocks, droppedNrbBlocks, totalFileBytes: buffer.byteLength };
}

/** Async framing via shared engine (MemoryAsyncCursor). */
export async function readPcapngFramed(buffer: ArrayBuffer): Promise<PcapngReadResult> {
  const payloads = new Map<number, Uint8Array>();
  const framed = await parsePcapngFraming(new MemoryAsyncCursor(buffer), {
    retainPayload: true,
    onPayload: (d, data) => payloads.set(d.packetNumber, data),
  });
  return framingToPcapngResult(framed, payloads);
}

/** Incremental production parse from Blob (no whole-file ArrayBuffer). */
export async function readPcapngFromBlob(blob: Blob): Promise<PcapngReadResult> {
  const framed = await parsePcapngFraming(new BlobSliceCursor(blob), { retainPayload: false });
  const payloads = await hydratePayloads(blob, framed.descriptors);
  return framingToPcapngResult(framed, payloads);
}

function framingToPcapngResult(
  framed: PcapngFramingResult,
  payloads: Map<number, Uint8Array>,
): PcapngReadResult {
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
  }));
  return { ...framed, packets };
}

function readIDB(
  cursor: BoundedCursor,
  le: boolean,
  sectionIndex: number,
  interfaces: PcapngInterfaceInfo[],
  sectionInterfaceStart: number,
): void {
  const linkType = le ? cursor.u16le() : cursor.u16be();
  cursor.skip(2); // reserved
  const snapLen = le ? cursor.u32le() : cursor.u32be();

  let tsResol: TimestampResolution = TimestampResolution.Microseconds;
  let tsResolValue = 6; // default 10^-6
  let tsOffset = 0n;

  // Parse options until we run out or hit end_of_opt
  // We don't know exact option section length without block body, so parse best-effort
  // Caller will seek to proper end after return
  try {
    while (cursor.remaining >= 4) {
      const optCode = le ? cursor.u16le() : cursor.u16be();
      const optLen = le ? cursor.u16le() : cursor.u16be();
      if (optCode === OPT_ENDOFOPT) break;
      const padded = (optLen + 3) & ~3;
      if (cursor.remaining < padded) break;

      if (optCode === OPT_IF_TSRESOL && optLen === 1) {
        const val = cursor.u8();
        tsResolValue = val;
        if (val & 0x80) {
          // power of 2
          tsResol = TimestampResolution.Nanoseconds; // approximate; actual is 2^(val&0x7f)
        } else {
          tsResol = val === 9 ? TimestampResolution.Nanoseconds : TimestampResolution.Microseconds;
        }
        cursor.skip(padded - 1);
      } else if (optCode === OPT_IF_TSOFFSET && optLen === 8) {
        tsOffset = le ? cursor.u64le() : cursor.u64be();
      } else {
        cursor.skip(padded);
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
  });
}

function makeTimestampFromHiLo(tsHigh: number, tsLow: number, iface: PcapngInterfaceInfo): PacketTimestamp {
  const rawTs = (BigInt(tsHigh) << 32n) | BigInt(tsLow >>> 0);
  const tsResolVal = iface.tsResolValue;
  let unitsPerSecond: bigint;
  if (tsResolVal & 0x80) {
    unitsPerSecond = 1n << BigInt(tsResolVal & 0x7f);
  } else {
    unitsPerSecond = 10n ** BigInt(tsResolVal);
  }
  return { ticks: rawTs, unitsPerSecond, offsetSeconds: iface.tsOffset };
}

function readEPB(
  cursor: BoundedCursor,
  le: boolean,
  sectionIndex: number,
  sectionInterfaceStart: number,
  interfaces: PcapngInterfaceInfo[],
  packets: PacketEnvelope[],
  descriptors: PacketRecordDescriptor[],
  issues: ParseIssue[],
  checkpoints: SparseCheckpoint[],
  blockFileOffset: number,
  packetNumber: number,
): void {
  const ifaceId = le ? cursor.u32le() : cursor.u32be();
  const tsHigh = le ? cursor.u32le() : cursor.u32be();
  const tsLow = le ? cursor.u32le() : cursor.u32be();
  const capturedLen = le ? cursor.u32le() : cursor.u32be();
  const originalLen = le ? cursor.u32le() : cursor.u32be();

  const globalIfaceIdx = sectionInterfaceStart + ifaceId;
  const iface = interfaces[globalIfaceIdx];
  if (!iface) {
    issues.push({
      severity: IssueSeverity.Error,
      code: 'pcapng-unknown-interface',
      message: `EPB packet ${packetNumber} references undefined interface ${ifaceId}`,
      packetNumber,
      fileOffset: blockFileOffset,
    });
    return;
  }

  if (capturedLen > cursor.remaining) {
    issues.push({
      severity: IssueSeverity.Error,
      code: 'pcapng-epb-truncated',
      message: `EPB packet ${packetNumber} data truncated`,
      packetNumber,
      fileOffset: blockFileOffset,
    });
    return;
  }

  const dataOffset = cursor.offset;
  const data = cursor.slice(capturedLen);
  const timestamp = makeTimestampFromHiLo(tsHigh, tsLow, iface);

  descriptors.push({
    packetNumber,
    timestamp,
    capturedLength: capturedLen,
    originalLength: originalLen,
    linkType: iface.linkType,
    interfaceId: ifaceId,
    sectionIndex,
    fileOffset: blockFileOffset,
    dataOffset,
  });

  packets.push({
    packetNumber,
    timestamp,
    capturedLength: capturedLen,
    originalLength: originalLen,
    linkType: iface.linkType,
    interfaceId: ifaceId,
    sectionIndex,
    fileOffset: blockFileOffset,
    data,
  });

  if (packetNumber % SPARSE_CHECKPOINT_INTERVAL === 0) {
    checkpoints.push({ packetNumber, fileOffset: blockFileOffset });
  }
}

function readSPB(
  cursor: BoundedCursor,
  le: boolean,
  sectionIndex: number,
  sectionInterfaceStart: number,
  interfaces: PcapngInterfaceInfo[],
  packets: PacketEnvelope[],
  descriptors: PacketRecordDescriptor[],
  issues: ParseIssue[],
  checkpoints: SparseCheckpoint[],
  blockFileOffset: number,
  packetNumber: number,
  bodyLen: number,
): void {
  const originalLen = le ? cursor.u32le() : cursor.u32be();
  const iface = interfaces[sectionInterfaceStart];
  if (!iface) {
    issues.push({
      severity: IssueSeverity.Error,
      code: 'pcapng-spb-no-interface',
      message: `SPB packet ${packetNumber}: no interface defined`,
      packetNumber,
      fileOffset: blockFileOffset,
    });
    return;
  }

  const capturedLen = Math.min(originalLen, iface.snapLen, bodyLen - 4);
  if (capturedLen > cursor.remaining) return;

  const dataOffset = cursor.offset;
  const data = cursor.slice(capturedLen);
  // SPB has no timestamp
  const timestamp: PacketTimestamp = { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n };

  descriptors.push({
    packetNumber,
    timestamp,
    capturedLength: capturedLen,
    originalLength: originalLen,
    linkType: iface.linkType,
    interfaceId: 0,
    sectionIndex,
    fileOffset: blockFileOffset,
    dataOffset,
  });

  packets.push({
    packetNumber,
    timestamp,
    capturedLength: capturedLen,
    originalLength: originalLen,
    linkType: iface.linkType,
    interfaceId: 0,
    sectionIndex,
    fileOffset: blockFileOffset,
    data,
  });

  if (packetNumber % SPARSE_CHECKPOINT_INTERVAL === 0) {
    checkpoints.push({ packetNumber, fileOffset: blockFileOffset });
  }
}

function readOPB(
  cursor: BoundedCursor,
  le: boolean,
  sectionIndex: number,
  sectionInterfaceStart: number,
  interfaces: PcapngInterfaceInfo[],
  packets: PacketEnvelope[],
  descriptors: PacketRecordDescriptor[],
  issues: ParseIssue[],
  checkpoints: SparseCheckpoint[],
  blockFileOffset: number,
  packetNumber: number,
): void {
  const ifaceId = le ? cursor.u16le() : cursor.u16be();
  cursor.skip(2); // drops_count
  const tsHigh = le ? cursor.u32le() : cursor.u32be();
  const tsLow = le ? cursor.u32le() : cursor.u32be();
  const capturedLen = le ? cursor.u32le() : cursor.u32be();
  const originalLen = le ? cursor.u32le() : cursor.u32be();

  const globalIfaceIdx = sectionInterfaceStart + ifaceId;
  const iface = interfaces[globalIfaceIdx];
  if (!iface) {
    issues.push({
      severity: IssueSeverity.Error,
      code: 'pcapng-unknown-interface',
      message: `OPB packet ${packetNumber} references undefined interface ${ifaceId}`,
      packetNumber,
      fileOffset: blockFileOffset,
    });
    return;
  }

  if (capturedLen > cursor.remaining) return;

  const dataOffset = cursor.offset;
  const data = cursor.slice(capturedLen);
  const timestamp = makeTimestampFromHiLo(tsHigh, tsLow, iface);

  descriptors.push({
    packetNumber,
    timestamp,
    capturedLength: capturedLen,
    originalLength: originalLen,
    linkType: iface.linkType,
    interfaceId: ifaceId,
    sectionIndex,
    fileOffset: blockFileOffset,
    dataOffset,
  });

  packets.push({
    packetNumber,
    timestamp,
    capturedLength: capturedLen,
    originalLength: originalLen,
    linkType: iface.linkType,
    interfaceId: ifaceId,
    sectionIndex,
    fileOffset: blockFileOffset,
    data,
  });

  if (packetNumber % SPARSE_CHECKPOINT_INTERVAL === 0) {
    checkpoints.push({ packetNumber, fileOffset: blockFileOffset });
  }
}

function swapU32(v: number): number {
  return (
    ((v & 0xff) << 24) |
    ((v & 0xff00) << 8) |
    ((v & 0xff0000) >>> 8) |
    ((v & 0xff000000) >>> 24)
  ) >>> 0;
}
