/**
 * PCAPNG writer. Produces a valid PCAPNG file from sections, interfaces and packets.
 * Implements:
 * - Correct block alignment (4 bytes)
 * - Matching leading/trailing total_length
 * - Positive option allowlist (only structural options preserved)
 * - Metadata stripping: NRB, DSB, ISB, comments, custom blocks are never written
 * - Padding written as zeros
 */

import type { PacketEnvelope, PcapngInterfaceInfo, PcapngSectionInfo } from '../domain/types';
import { Endian, PCAPNG_BYTE_ORDER_MAGIC } from '../domain/types';

export interface PcapngWriteOptions {
  readonly sections: readonly PcapngSectionInfo[];
  readonly interfaces: readonly PcapngInterfaceInfo[];
  readonly packets: readonly PacketEnvelope[];
}

// Block type constants
const BT_SHB = 0x0a0d0d0a;
const BT_IDB = 0x00000001;
const BT_EPB = 0x00000006;

// Option codes
const OPT_ENDOFOPT = 0;
const OPT_IF_TSRESOL = 9;
const OPT_IF_TSOFFSET = 14;

export function writePcapng(opts: PcapngWriteOptions): ArrayBuffer {
  const chunks: ArrayBuffer[] = [];
  const writer = createPcapngIncrementalWriter({
    sections: opts.sections,
    interfaces: opts.interfaces,
  });

  if (opts.packets.length === 0) {
    for (const section of opts.sections) {
      chunks.push(writePcapngSHB(section));
      for (const iface of opts.interfaces.filter((i) => i.sectionIndex === section.sectionIndex)) {
        chunks.push(writePcapngIDB(iface, section.endian));
      }
    }
  } else {
    for (const pkt of opts.packets) {
      chunks.push(...writer.emitPacket(pkt));
    }
  }

  return concatPcapngChunks(chunks);
}

export function concatPcapngChunks(chunks: readonly ArrayBuffer[]): ArrayBuffer {
  let totalSize = 0;
  for (const c of chunks) totalSize += c.byteLength;
  const result = new ArrayBuffer(totalSize);
  const out = new Uint8Array(result);
  let offset = 0;
  for (const c of chunks) {
    out.set(new Uint8Array(c), offset);
    offset += c.byteLength;
  }
  return result;
}

export interface PcapngIncrementalWriter {
  emitPacket(pkt: PacketEnvelope): ArrayBuffer[];
}

export function createPcapngIncrementalWriter(input: {
  sections: readonly PcapngSectionInfo[];
  interfaces: readonly PcapngInterfaceInfo[];
}): PcapngIncrementalWriter {
  let currentSectionIdx = -1;
  return {
    emitPacket(pkt: PacketEnvelope): ArrayBuffer[] {
      const chunks: ArrayBuffer[] = [];
      if (pkt.sectionIndex !== currentSectionIdx) {
        currentSectionIdx = pkt.sectionIndex;
        const section = input.sections[currentSectionIdx];
        if (section) {
          chunks.push(writePcapngSHB(section));
        }
        for (const iface of input.interfaces.filter((i) => i.sectionIndex === currentSectionIdx)) {
          chunks.push(writePcapngIDB(iface, section?.endian ?? Endian.Little));
        }
      }
      const section = input.sections[currentSectionIdx];
      chunks.push(writePcapngEPB(pkt, section?.endian ?? Endian.Little));
      return chunks;
    },
  };
}

export function writePcapngSHB(section: PcapngSectionInfo): ArrayBuffer {
  return writeSHB(section);
}

export function writePcapngIDB(iface: PcapngInterfaceInfo, endian: Endian): ArrayBuffer {
  return writeIDB(iface, endian);
}

export function writePcapngEPB(pkt: PacketEnvelope, endian: Endian): ArrayBuffer {
  return writeEPB(pkt, endian);
}

function writeSHB(section: PcapngSectionInfo): ArrayBuffer {
  const le = section.endian === Endian.Little;
  const totalLen = 28; // fixed SHB without options
  const buf = new ArrayBuffer(totalLen);
  const view = new DataView(buf);

  view.setUint32(0, BT_SHB, le);
  view.setUint32(4, totalLen, le);
  view.setUint32(8, le ? PCAPNG_BYTE_ORDER_MAGIC : PCAPNG_BYTE_ORDER_MAGIC, le);
  view.setUint16(12, section.versionMajor, le);
  view.setUint16(14, section.versionMinor, le);
  // section length = -1 (unspecified)
  view.setBigInt64(16, -1n, le);
  view.setUint32(24, totalLen, le); // trailing

  return buf;
}

function writeIDB(iface: PcapngInterfaceInfo, endian: Endian): ArrayBuffer {
  const le = endian === Endian.Little;

  // Options: if_tsresol (always write) + optionally if_tsoffset + end_of_opt
  const options: ArrayBuffer[] = [];

  // if_tsresol: code=9, len=1, padded to 4
  const tsResolOpt = new ArrayBuffer(8);
  const tsResolView = new DataView(tsResolOpt);
  tsResolView.setUint16(0, OPT_IF_TSRESOL, le);
  tsResolView.setUint16(2, 1, le);
  new Uint8Array(tsResolOpt)[4] = iface.tsResolValue;
  // bytes 5,6,7 are zero padding
  options.push(tsResolOpt);

  // if_tsoffset if non-zero
  if (iface.tsOffset !== 0n) {
    const tsOffOpt = new ArrayBuffer(12);
    const tsOffView = new DataView(tsOffOpt);
    tsOffView.setUint16(0, OPT_IF_TSOFFSET, le);
    tsOffView.setUint16(2, 8, le);
    tsOffView.setBigInt64(4, iface.tsOffset, le);
    options.push(tsOffOpt);
  }

  // end_of_opt
  const endOpt = new ArrayBuffer(4);
  const endView = new DataView(endOpt);
  endView.setUint16(0, OPT_ENDOFOPT, le);
  endView.setUint16(2, 0, le);
  options.push(endOpt);

  let optionsLen = 0;
  for (const o of options) optionsLen += o.byteLength;

  // IDB body: linkType(2) + reserved(2) + snapLen(4) + options
  const bodyLen = 8 + optionsLen;
  const totalLen = 12 + bodyLen; // type + len + body + trailing
  const buf = new ArrayBuffer(totalLen);
  const view = new DataView(buf);
  const bytes = new Uint8Array(buf);

  view.setUint32(0, BT_IDB, le);
  view.setUint32(4, totalLen, le);
  view.setUint16(8, iface.linkType, le);
  view.setUint16(10, 0, le); // reserved
  view.setUint32(12, iface.snapLen, le);

  // Write options
  let off = 16;
  for (const o of options) {
    bytes.set(new Uint8Array(o), off);
    off += o.byteLength;
  }

  view.setUint32(totalLen - 4, totalLen, le); // trailing

  return buf;
}

function writeEPB(pkt: PacketEnvelope, endian: Endian): ArrayBuffer {
  const le = endian === Endian.Little;
  const paddedDataLen = (pkt.capturedLength + 3) & ~3;
  // EPB: type(4) + totalLen(4) + iface(4) + tsH(4) + tsL(4) + capLen(4) + origLen(4) + data(padded) + trailing(4)
  const totalLen = 32 + paddedDataLen;
  const buf = new ArrayBuffer(totalLen);
  const view = new DataView(buf);

  view.setUint32(0, BT_EPB, le);
  view.setUint32(4, totalLen, le);
  view.setUint32(8, pkt.interfaceId, le);

  // Timestamp as high/low 32-bit
  const tsHigh = Number((pkt.timestamp.ticks >> 32n) & 0xffffffffn);
  const tsLow = Number(pkt.timestamp.ticks & 0xffffffffn);
  view.setUint32(12, tsHigh, le);
  view.setUint32(16, tsLow, le);

  view.setUint32(20, pkt.capturedLength, le);
  view.setUint32(24, pkt.originalLength, le);

  // Packet data + zero padding
  new Uint8Array(buf, 28, pkt.capturedLength).set(pkt.data.subarray(0, pkt.capturedLength));
  // remaining padding bytes are already zero from ArrayBuffer allocation

  view.setUint32(totalLen - 4, totalLen, le); // trailing

  return buf;
}
