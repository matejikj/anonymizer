/**
 * Classic PCAP writer. Produces a valid PCAP file from header + packet envelopes.
 * Preserves endian and timestamp resolution of the original capture.
 */

import type { ClassicPcapHeader, PacketEnvelope } from '../domain/types';
import { Endian, TimestampResolution, PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_MICRO_BE, PCAP_MAGIC_NANO_LE, PCAP_MAGIC_NANO_BE } from '../domain/types';

export interface PcapWriteOptions {
  readonly header: ClassicPcapHeader;
  readonly packets: readonly PacketEnvelope[];
}

export function writeClassicPcap(opts: PcapWriteOptions): ArrayBuffer {
  const { header, packets } = opts;
  const chunks: ArrayBuffer[] = [writeClassicPcapGlobalHeader(header)];
  for (const pkt of packets) {
    chunks.push(writeClassicPcapRecord(header, pkt));
  }
  return concatArrayBuffers(chunks);
}

/** Incremental classic PCAP — global header chunk (24 bytes). */
export function writeClassicPcapGlobalHeader(header: ClassicPcapHeader): ArrayBuffer {
  const le = header.endian === Endian.Little;
  const buffer = new ArrayBuffer(24);
  const view = new DataView(buffer);
  let offset = 0;
  const magic = getMagic(header.endian, header.timestampResolution);
  view.setUint32(offset, magic, true); offset += 4;
  setU16(view, offset, header.versionMajor, le); offset += 2;
  setU16(view, offset, header.versionMinor, le); offset += 2;
  setI32(view, offset, header.tzOffset, le); offset += 4;
  setU32(view, offset, header.sigfigs, le); offset += 4;
  setU32(view, offset, header.snapLen, le); offset += 4;
  setU32(view, offset, header.linkType, le); offset += 4;
  return buffer;
}

/** Incremental classic PCAP — one record chunk (16-byte header + payload). */
export function writeClassicPcapRecord(header: ClassicPcapHeader, pkt: PacketEnvelope): ArrayBuffer {
  const le = header.endian === Endian.Little;
  const unitsPerSecond = header.timestampResolution === TimestampResolution.Nanoseconds
    ? 1_000_000_000n
    : 1_000_000n;
  const tsSec = Number(pkt.timestamp.ticks / unitsPerSecond);
  const tsFrac = Number(pkt.timestamp.ticks % unitsPerSecond);
  const buffer = new ArrayBuffer(16 + pkt.capturedLength);
  const view = new DataView(buffer);
  let offset = 0;
  setU32(view, offset, tsSec, le); offset += 4;
  setU32(view, offset, tsFrac, le); offset += 4;
  setU32(view, offset, pkt.capturedLength, le); offset += 4;
  setU32(view, offset, pkt.originalLength, le); offset += 4;
  new Uint8Array(buffer, offset, pkt.capturedLength).set(pkt.data.subarray(0, pkt.capturedLength));
  return buffer;
}

export function concatArrayBuffers(chunks: readonly ArrayBuffer[]): ArrayBuffer {
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

function getMagic(endian: Endian, tsResol: TimestampResolution): number {
  if (endian === Endian.Little) {
    return tsResol === TimestampResolution.Nanoseconds ? PCAP_MAGIC_NANO_LE : PCAP_MAGIC_MICRO_LE;
  }
  return tsResol === TimestampResolution.Nanoseconds ? PCAP_MAGIC_NANO_BE : PCAP_MAGIC_MICRO_BE;
}

function setU16(view: DataView, offset: number, val: number, le: boolean): void {
  view.setUint16(offset, val, le);
}

function setU32(view: DataView, offset: number, val: number, le: boolean): void {
  view.setUint32(offset, val >>> 0, le);
}

function setI32(view: DataView, offset: number, val: number, le: boolean): void {
  view.setInt32(offset, val, le);
}
