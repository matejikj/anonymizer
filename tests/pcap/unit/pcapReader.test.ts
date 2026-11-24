import { describe, it, expect } from 'vitest';
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader';
import { probeFormat } from '../../../src/pcap/capture/probe';
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types';

function makeMinimalPcap(opts?: { magic?: number; packets?: number }): ArrayBuffer {
  const magic = opts?.magic ?? 0xa1b2c3d4;
  const packetCount = opts?.packets ?? 1;
  const packetData = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const size = 24 + packetCount * (16 + packetData.length);
  const buf = new ArrayBuffer(size);
  const view = new DataView(buf);

  view.setUint32(0, magic, true);
  view.setUint16(4, 2, true); // major
  view.setUint16(6, 4, true); // minor
  view.setInt32(8, 0, true); // tz
  view.setUint32(12, 0, true); // sigfigs
  view.setUint32(16, 65535, true); // snaplen
  view.setUint32(20, 1, true); // ethernet

  let offset = 24;
  for (let i = 0; i < packetCount; i++) {
    view.setUint32(offset, 1700000000 + i, true); // ts_sec
    view.setUint32(offset + 4, i * 1000, true); // ts_usec
    view.setUint32(offset + 8, packetData.length, true); // incl_len
    view.setUint32(offset + 12, packetData.length, true); // orig_len
    new Uint8Array(buf, offset + 16, packetData.length).set(packetData);
    offset += 16 + packetData.length;
  }

  return buf;
}

describe('probeFormat', () => {
  it('detects classic PCAP LE micro', () => {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(0, 0xa1b2c3d4, true);
    expect(probeFormat(buf)).toEqual({ format: CaptureFormat.ClassicPcap });
  });

  it('detects PCAPNG', () => {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(0, 0x0a0d0d0a, true);
    expect(probeFormat(buf)).toEqual({ format: CaptureFormat.Pcapng });
  });

  it('rejects unknown', () => {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(0, 0xdeadbeef, true);
    const r = probeFormat(buf);
    expect(r.format).toBeNull();
  });
});

describe('readClassicPcap', () => {
  it('reads minimal pcap with one packet', () => {
    const buf = makeMinimalPcap();
    const result = readClassicPcap(buf);

    expect(result.header.format).toBe(CaptureFormat.ClassicPcap);
    expect(result.header.endian).toBe(Endian.Little);
    expect(result.header.timestampResolution).toBe(TimestampResolution.Microseconds);
    expect(result.header.linkType).toBe(1);
    expect(result.packets.length).toBe(1);
    expect(result.packets[0]!.capturedLength).toBe(4);
    expect(result.packets[0]!.data).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    expect(result.issues.length).toBe(0);
  });

  it('reads multiple packets', () => {
    const buf = makeMinimalPcap({ packets: 10 });
    const result = readClassicPcap(buf);
    expect(result.packets.length).toBe(10);
    expect(result.packets[9]!.packetNumber).toBe(9);
  });

  it('detects nano timestamp resolution', () => {
    const buf = makeMinimalPcap({ magic: 0xa1b23c4d });
    const result = readClassicPcap(buf);
    expect(result.header.timestampResolution).toBe(TimestampResolution.Nanoseconds);
    expect(result.packets[0]!.timestamp.unitsPerSecond).toBe(1_000_000_000n);
  });

  it('reports truncated packet', () => {
    const buf = new ArrayBuffer(24 + 16 + 2); // header + record header + only 2 bytes (less than incl_len=4)
    const view = new DataView(buf);
    view.setUint32(0, 0xa1b2c3d4, true);
    view.setUint16(4, 2, true);
    view.setUint16(6, 4, true);
    view.setUint32(16, 65535, true);
    view.setUint32(20, 1, true);
    // record: incl_len=4 but only 2 bytes available
    view.setUint32(24 + 8, 4, true);
    view.setUint32(24 + 12, 4, true);

    const result = readClassicPcap(buf);
    expect(result.packets.length).toBe(0);
    expect(result.issues.length).toBe(1);
    expect(result.issues[0]!.code).toBe('pcap-truncated');
  });

  it('creates sparse checkpoints', () => {
    const buf = makeMinimalPcap({ packets: 5000 });
    const result = readClassicPcap(buf);
    expect(result.checkpoints.length).toBe(2); // packet 0 and 4096
    expect(result.checkpoints[0]!.packetNumber).toBe(0);
    expect(result.checkpoints[1]!.packetNumber).toBe(4096);
  });
});
