import { describe, it, expect } from 'vitest';
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader';
import { readPcapng } from '../../../src/pcap/capture/pcapngReader';
import { validateClassicPcap, validatePcapng } from '../../../src/pcap/capture/validator';
import { IssueSeverity } from '../../../src/pcap/domain/types';

describe('Malformed classic PCAP inputs', () => {
  it('empty buffer does not crash', () => {
    const buf = new ArrayBuffer(0);
    const validation = validateClassicPcap(buf);
    expect(validation.valid).toBe(false);
  });

  it('too small buffer (< 24)', () => {
    const buf = new ArrayBuffer(10);
    const validation = validateClassicPcap(buf);
    expect(validation.valid).toBe(false);
    expect(validation.issues[0]!.code).toBe('val-too-small');
  });

  it('invalid magic', () => {
    const buf = new ArrayBuffer(24);
    new DataView(buf).setUint32(0, 0xdeadbeef, true);
    const validation = validateClassicPcap(buf);
    expect(validation.valid).toBe(false);
    expect(validation.issues[0]!.code).toBe('val-bad-magic');
  });

  it('packet with huge incl_len does not allocate', () => {
    const buf = new ArrayBuffer(24 + 16);
    const dv = new DataView(buf);
    dv.setUint32(0, 0xa1b2c3d4, true); // magic
    dv.setUint16(4, 2, true); dv.setUint16(6, 4, true); // version
    dv.setUint32(16, 65535, true); // snaplen
    dv.setUint32(20, 1, true); // linktype
    // Record with impossibly large incl_len
    dv.setUint32(24 + 8, 0x7fffffff, true); // incl_len
    dv.setUint32(24 + 12, 0x7fffffff, true); // orig_len

    const result = readClassicPcap(buf);
    expect(result.packets.length).toBe(0);
    expect(result.issues.length).toBeGreaterThan(0);
  });

  it('truncated packet record', () => {
    const buf = new ArrayBuffer(24 + 16 + 2); // only 2 of 4 claimed data bytes
    const dv = new DataView(buf);
    dv.setUint32(0, 0xa1b2c3d4, true);
    dv.setUint16(4, 2, true); dv.setUint16(6, 4, true);
    dv.setUint32(16, 65535, true);
    dv.setUint32(20, 1, true);
    dv.setUint32(24 + 8, 4, true); // claims 4 bytes
    dv.setUint32(24 + 12, 4, true);

    const result = readClassicPcap(buf);
    expect(result.packets.length).toBe(0);
    expect(result.issues.some(i => i.code === 'pcap-truncated')).toBe(true);
  });

  it('record too large triggers fatal issue', () => {
    const buf = new ArrayBuffer(24 + 16);
    const dv = new DataView(buf);
    dv.setUint32(0, 0xa1b2c3d4, true);
    dv.setUint16(4, 2, true); dv.setUint16(6, 4, true);
    dv.setUint32(16, 65535, true);
    dv.setUint32(20, 1, true);
    dv.setUint32(24 + 8, 20_000_000, true); // > 16 MiB cap
    dv.setUint32(24 + 12, 20_000_000, true);

    const result = readClassicPcap(buf);
    expect(result.issues.some(i => i.severity === IssueSeverity.Fatal)).toBe(true);
  });
});

describe('Malformed PCAPNG inputs', () => {
  it('empty buffer does not crash', () => {
    const buf = new ArrayBuffer(0);
    const validation = validatePcapng(buf);
    expect(validation.valid).toBe(false);
  });

  it('block with length < 12', () => {
    const buf = new ArrayBuffer(28 + 12);
    const dv = new DataView(buf);
    // Valid SHB first
    dv.setUint32(0, 0x0a0d0d0a, true);
    dv.setUint32(4, 28, true);
    dv.setUint32(8, 0x1a2b3c4d, true);
    dv.setUint16(12, 1, true);
    dv.setUint16(14, 0, true);
    dv.setBigInt64(16, -1n, true);
    dv.setUint32(24, 28, true);
    // Bad block
    dv.setUint32(28, 0x00000099, true); // unknown type
    dv.setUint32(32, 8, true); // length 8 < 12

    const result = readPcapng(buf);
    expect(result.issues.some(i => i.code === 'pcapng-bad-block-length')).toBe(true);
  });

  it('block with non-aligned length', () => {
    const buf = new ArrayBuffer(28 + 12);
    const dv = new DataView(buf);
    dv.setUint32(0, 0x0a0d0d0a, true);
    dv.setUint32(4, 28, true);
    dv.setUint32(8, 0x1a2b3c4d, true);
    dv.setUint16(12, 1, true);
    dv.setUint16(14, 0, true);
    dv.setBigInt64(16, -1n, true);
    dv.setUint32(24, 28, true);
    // Block with odd length
    dv.setUint32(28, 0x00000099, true);
    dv.setUint32(32, 13, true); // not multiple of 4

    const result = readPcapng(buf);
    expect(result.issues.some(i => i.code === 'pcapng-bad-block-length')).toBe(true);
  });

  it('block with huge totalLen does not allocate', () => {
    const buf = new ArrayBuffer(28 + 12);
    const dv = new DataView(buf);
    dv.setUint32(0, 0x0a0d0d0a, true);
    dv.setUint32(4, 28, true);
    dv.setUint32(8, 0x1a2b3c4d, true);
    dv.setUint16(12, 1, true);
    dv.setUint16(14, 0, true);
    dv.setBigInt64(16, -1n, true);
    dv.setUint32(24, 28, true);
    // Block claiming 100 MiB
    dv.setUint32(28, 0x00000099, true);
    dv.setUint32(32, 100 * 1024 * 1024, true);

    const result = readPcapng(buf);
    expect(result.issues.some(i => i.severity === IssueSeverity.Fatal)).toBe(true);
  });

  it('EPB referencing undefined interface', () => {
    // SHB(28) + IDB(20) + EPB referencing interface 5
    const epbLen = 36;
    const buf = new ArrayBuffer(28 + 20 + epbLen);
    const dv = new DataView(buf);
    // SHB
    dv.setUint32(0, 0x0a0d0d0a, true);
    dv.setUint32(4, 28, true);
    dv.setUint32(8, 0x1a2b3c4d, true);
    dv.setUint16(12, 1, true); dv.setUint16(14, 0, true);
    dv.setBigInt64(16, -1n, true);
    dv.setUint32(24, 28, true);
    // IDB
    dv.setUint32(28, 0x00000001, true);
    dv.setUint32(32, 20, true);
    dv.setUint16(36, 1, true);
    dv.setUint32(40, 262144, true);
    dv.setUint32(44, 20, true);
    // EPB with bad interface
    const epbOff = 48;
    dv.setUint32(epbOff, 0x00000006, true);
    dv.setUint32(epbOff + 4, epbLen, true);
    dv.setUint32(epbOff + 8, 5, true); // interface 5 doesn't exist
    dv.setUint32(epbOff + 20, 4, true); // caplen
    dv.setUint32(epbOff + 24, 4, true); // origlen
    dv.setUint32(epbOff + epbLen - 4, epbLen, true);

    const result = readPcapng(buf);
    expect(result.issues.some(i => i.code === 'pcapng-unknown-interface')).toBe(true);
  });

  it('invalid BOM in SHB', () => {
    const buf = new ArrayBuffer(28);
    const dv = new DataView(buf);
    dv.setUint32(0, 0x0a0d0d0a, true);
    dv.setUint32(4, 28, true);
    dv.setUint32(8, 0xdeadbeef, true); // bad BOM
    dv.setUint16(12, 1, true); dv.setUint16(14, 0, true);
    dv.setBigInt64(16, -1n, true);
    dv.setUint32(24, 28, true);

    const result = readPcapng(buf);
    expect(result.issues.some(i => i.code === 'pcapng-bad-bom')).toBe(true);
  });
});

describe('Validator rejects invalid output', () => {
  it('validator catches mismatched trailing length in PCAPNG', () => {
    const buf = new ArrayBuffer(28);
    const dv = new DataView(buf);
    dv.setUint32(0, 0x0a0d0d0a, true);
    dv.setUint32(4, 28, true);
    dv.setUint32(8, 0x1a2b3c4d, true);
    dv.setUint16(12, 1, true); dv.setUint16(14, 0, true);
    dv.setBigInt64(16, -1n, true);
    dv.setUint32(24, 99, true); // wrong trailing

    const result = validatePcapng(buf);
    expect(result.issues.some(i => i.code === 'val-trailing-mismatch')).toBe(true);
  });

  it('validator catches timestamp fraction out of range', () => {
    const buf = new ArrayBuffer(24 + 16 + 4);
    const dv = new DataView(buf);
    dv.setUint32(0, 0xa1b2c3d4, true); // micro
    dv.setUint16(4, 2, true); dv.setUint16(6, 4, true);
    dv.setUint32(16, 65535, true);
    dv.setUint32(20, 1, true);
    // Packet with invalid usec
    dv.setUint32(24, 1700000000, true); // ts_sec
    dv.setUint32(28, 2000000, true); // ts_usec > 999999
    dv.setUint32(32, 4, true); // incl
    dv.setUint32(36, 4, true); // orig

    const result = validateClassicPcap(buf);
    expect(result.issues.some(i => i.code === 'val-ts-frac-range')).toBe(true);
  });
});
