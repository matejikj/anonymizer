import { describe, it, expect } from 'vitest';
import { readPcapng } from '../../../src/pcap/capture/pcapngReader';

function makeMinimalPcapng(packetCount = 1): ArrayBuffer {
  // SHB(28) + IDB(20) + EPBs
  const packetData = new Uint8Array([0xca, 0xfe, 0xba, 0xbe]);
  const paddedDataLen = (packetData.length + 3) & ~3;
  const epbLen = 12 + 20 + paddedDataLen; // type+len+trailing + iface+tsH+tsL+cap+orig + padded data
  const totalSize = 28 + 20 + packetCount * epbLen;
  const buf = new ArrayBuffer(totalSize);
  const view = new DataView(buf);
  let off = 0;

  // SHB
  view.setUint32(off, 0x0a0d0d0a, true); off += 4;
  view.setUint32(off, 28, true); off += 4;
  view.setUint32(off, 0x1a2b3c4d, true); off += 4; // BOM
  view.setUint16(off, 1, true); off += 2; // major
  view.setUint16(off, 0, true); off += 2; // minor
  view.setBigInt64(off, -1n, true); off += 8; // section length
  view.setUint32(off, 28, true); off += 4; // trailing

  // IDB
  view.setUint32(off, 0x00000001, true); off += 4;
  view.setUint32(off, 20, true); off += 4;
  view.setUint16(off, 1, true); off += 2; // link type ethernet
  view.setUint16(off, 0, true); off += 2; // reserved
  view.setUint32(off, 262144, true); off += 4; // snaplen
  view.setUint32(off, 20, true); off += 4; // trailing

  // EPBs
  for (let i = 0; i < packetCount; i++) {
    view.setUint32(off, 0x00000006, true); off += 4; // EPB type
    view.setUint32(off, epbLen, true); off += 4; // total length
    view.setUint32(off, 0, true); off += 4; // interface id
    view.setUint32(off, 0, true); off += 4; // ts high
    view.setUint32(off, i * 1000, true); off += 4; // ts low
    view.setUint32(off, packetData.length, true); off += 4; // captured
    view.setUint32(off, packetData.length, true); off += 4; // original
    new Uint8Array(buf, off, packetData.length).set(packetData);
    off += paddedDataLen;
    view.setUint32(off, epbLen, true); off += 4; // trailing
  }

  return buf;
}

describe('readPcapng', () => {
  it('reads minimal PCAPNG with one packet', () => {
    const buf = makeMinimalPcapng(1);
    const result = readPcapng(buf);

    expect(result.sections.length).toBe(1);
    expect(result.interfaces.length).toBe(1);
    expect(result.interfaces[0]!.linkType).toBe(1);
    expect(result.packets.length).toBe(1);
    expect(result.packets[0]!.capturedLength).toBe(4);
    expect(result.packets[0]!.data).toEqual(new Uint8Array([0xca, 0xfe, 0xba, 0xbe]));
    expect(result.issues.length).toBe(0);
  });

  it('reads multiple packets', () => {
    const buf = makeMinimalPcapng(50);
    const result = readPcapng(buf);
    expect(result.packets.length).toBe(50);
    expect(result.packets[49]!.packetNumber).toBe(49);
  });

  it('detects DSB/NRB as dropped metadata', () => {
    // Add an NRB block after IDB
    const base = makeMinimalPcapng(0);
    // NRB: type(4) + len(4) + trailing(4) = 12 (minimum)
    const nrb = new ArrayBuffer(12);
    const nv = new DataView(nrb);
    nv.setUint32(0, 0x00000004, true); // NRB
    nv.setUint32(4, 12, true);
    nv.setUint32(8, 12, true);

    const combined = new Uint8Array(base.byteLength + nrb.byteLength);
    combined.set(new Uint8Array(base), 0);
    combined.set(new Uint8Array(nrb), base.byteLength);

    const result = readPcapng(combined.buffer);
    expect(result.droppedMetadataBlocks).toBe(1);
  });

  it('reports bad block length', () => {
    const buf = new ArrayBuffer(28 + 20 + 12);
    const view = new DataView(buf);
    // SHB
    view.setUint32(0, 0x0a0d0d0a, true);
    view.setUint32(4, 28, true);
    view.setUint32(8, 0x1a2b3c4d, true);
    view.setUint16(12, 1, true);
    view.setUint16(14, 0, true);
    view.setBigInt64(16, -1n, true);
    view.setUint32(24, 28, true);
    // IDB
    view.setUint32(28, 0x00000001, true);
    view.setUint32(32, 20, true);
    view.setUint16(36, 1, true);
    view.setUint32(40, 262144, true);
    view.setUint32(44, 20, true);
    // Bad block: length 7 (not multiple of 4)
    view.setUint32(48, 0x000000ff, true); // unknown type
    view.setUint32(52, 7, true); // bad length

    const result = readPcapng(buf);
    expect(result.issues.some(i => i.code === 'pcapng-bad-block-length')).toBe(true);
  });
});
