import { describe, it, expect } from 'vitest';
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader';
import { readPcapng } from '../../../src/pcap/capture/pcapngReader';
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter';
import { writePcapng } from '../../../src/pcap/capture/pcapngWriter';
import { validateClassicPcap, validatePcapng } from '../../../src/pcap/capture/validator';
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types';
import type { ClassicPcapHeader, PacketEnvelope, PacketTimestamp } from '../../../src/pcap/domain/types';

function makePcapPackets(count: number): PacketEnvelope[] {
  const packets: PacketEnvelope[] = [];
  for (let i = 0; i < count; i++) {
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef, i & 0xff]);
    const ts: PacketTimestamp = { ticks: BigInt(1700000000) * 1000000n + BigInt(i) * 1000n, unitsPerSecond: 1000000n, offsetSeconds: 0n };
    packets.push({
      packetNumber: i,
      timestamp: ts,
      capturedLength: data.length,
      originalLength: data.length,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: 0,
      data,
    });
  }
  return packets;
}

describe('Classic PCAP round-trip', () => {
  const variants: Array<{ name: string; endian: Endian; tsResol: TimestampResolution }> = [
    { name: 'LE micro', endian: Endian.Little, tsResol: TimestampResolution.Microseconds },
    { name: 'LE nano', endian: Endian.Little, tsResol: TimestampResolution.Nanoseconds },
    { name: 'BE micro', endian: Endian.Big, tsResol: TimestampResolution.Microseconds },
    { name: 'BE nano', endian: Endian.Big, tsResol: TimestampResolution.Nanoseconds },
  ];

  for (const v of variants) {
    it(`identity round-trip (${v.name})`, () => {
      const header: ClassicPcapHeader = {
        format: CaptureFormat.ClassicPcap,
        endian: v.endian,
        timestampResolution: v.tsResol,
        versionMajor: 2,
        versionMinor: 4,
        snapLen: 65535,
        linkType: 1,
        tzOffset: 0,
        sigfigs: 0,
      };
      const packets = makePcapPackets(10);

      const written = writeClassicPcap({ header, packets });

      // Validate
      const validation = validateClassicPcap(written);
      expect(validation.valid).toBe(true);
      expect(validation.packetCount).toBe(10);
      expect(validation.issues.filter(i => i.severity > 0)).toHaveLength(0);

      // Re-read
      const reread = readClassicPcap(written);
      expect(reread.header.endian).toBe(v.endian);
      expect(reread.header.timestampResolution).toBe(v.tsResol);
      expect(reread.packets.length).toBe(10);

      // Verify data integrity
      for (let i = 0; i < 10; i++) {
        expect(reread.packets[i]!.capturedLength).toBe(packets[i]!.capturedLength);
        expect(reread.packets[i]!.originalLength).toBe(packets[i]!.originalLength);
        expect(Array.from(reread.packets[i]!.data)).toEqual(Array.from(packets[i]!.data));
      }

      // Verify timestamps preserved
      for (let i = 0; i < 10; i++) {
        expect(reread.packets[i]!.timestamp.ticks).toBe(packets[i]!.timestamp.ticks);
      }
    });
  }
});

describe('PCAPNG round-trip', () => {
  it('identity round-trip with one section and interface', () => {
    const sections = [{ sectionIndex: 0, endian: Endian.Little, versionMajor: 1, versionMinor: 0, sectionLength: -1n }];
    const interfaces = [{ interfaceId: 0, sectionIndex: 0, linkType: 1, snapLen: 262144, tsResol: TimestampResolution.Microseconds, tsResolValue: 6, tsOffset: 0n }];
    const packets = makePcapPackets(5);

    const written = writePcapng({ sections, interfaces, packets });

    // Validate
    const validation = validatePcapng(written);
    expect(validation.valid).toBe(true);
    expect(validation.packetCount).toBe(5);

    // Re-read
    const reread = readPcapng(written);
    expect(reread.sections.length).toBe(1);
    expect(reread.interfaces.length).toBe(1);
    expect(reread.packets.length).toBe(5);

    for (let i = 0; i < 5; i++) {
      expect(Array.from(reread.packets[i]!.data)).toEqual(Array.from(packets[i]!.data));
      expect(reread.packets[i]!.timestamp.ticks).toBe(packets[i]!.timestamp.ticks);
    }
  });

  it('multi-section with different endian', () => {
    const sections = [
      { sectionIndex: 0, endian: Endian.Little, versionMajor: 1, versionMinor: 0, sectionLength: -1n },
      { sectionIndex: 1, endian: Endian.Big, versionMajor: 1, versionMinor: 0, sectionLength: -1n },
    ];
    const interfaces = [
      { interfaceId: 0, sectionIndex: 0, linkType: 1, snapLen: 262144, tsResol: TimestampResolution.Microseconds, tsResolValue: 6, tsOffset: 0n },
      { interfaceId: 0, sectionIndex: 1, linkType: 1, snapLen: 262144, tsResol: TimestampResolution.Nanoseconds, tsResolValue: 9, tsOffset: 0n },
    ];

    const pkt0: PacketEnvelope = {
      packetNumber: 0, timestamp: { ticks: 100000n, unitsPerSecond: 1000000n, offsetSeconds: 0n },
      capturedLength: 4, originalLength: 4, linkType: 1, interfaceId: 0, sectionIndex: 0, fileOffset: 0,
      data: new Uint8Array([1, 2, 3, 4]),
    };
    const pkt1: PacketEnvelope = {
      packetNumber: 1, timestamp: { ticks: 200000000n, unitsPerSecond: 1000000000n, offsetSeconds: 0n },
      capturedLength: 3, originalLength: 3, linkType: 1, interfaceId: 0, sectionIndex: 1, fileOffset: 0,
      data: new Uint8Array([5, 6, 7]),
    };

    const written = writePcapng({ sections, interfaces, packets: [pkt0, pkt1] });
    const validation = validatePcapng(written);
    expect(validation.valid).toBe(true);
    expect(validation.packetCount).toBe(2);

    const reread = readPcapng(written);
    expect(reread.sections.length).toBe(2);
    expect(reread.packets.length).toBe(2);
    expect(Array.from(reread.packets[0]!.data)).toEqual([1, 2, 3, 4]);
    expect(Array.from(reread.packets[1]!.data)).toEqual([5, 6, 7]);
  });

  it('preserves bigint timestamp precision', () => {
    const sections = [{ sectionIndex: 0, endian: Endian.Little, versionMajor: 1, versionMinor: 0, sectionLength: -1n }];
    const interfaces = [{ interfaceId: 0, sectionIndex: 0, linkType: 1, snapLen: 262144, tsResol: TimestampResolution.Nanoseconds, tsResolValue: 9, tsOffset: 100n }];

    const highPrecisionTicks = 1700000000_123456789n;
    const pkt: PacketEnvelope = {
      packetNumber: 0, timestamp: { ticks: highPrecisionTicks, unitsPerSecond: 1000000000n, offsetSeconds: 100n },
      capturedLength: 2, originalLength: 2, linkType: 1, interfaceId: 0, sectionIndex: 0, fileOffset: 0,
      data: new Uint8Array([0xab, 0xcd]),
    };

    const written = writePcapng({ sections, interfaces, packets: [pkt] });
    const reread = readPcapng(written);

    // Verify ticks are exactly preserved (no floating-point precision loss)
    expect(reread.packets[0]!.timestamp.ticks).toBe(highPrecisionTicks);
  });
});
