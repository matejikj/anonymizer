import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader';
import { analyzePackets, getPacketPage } from '../../../src/pcap/protocols/analysis';

const SQUELCH_DIR = join(import.meta.dirname ?? '.', '..', '..', '..');

describe('Protocol decoders on synthetic packets', () => {
  it('decodes Ethernet/IPv4/TCP packet', () => {
    // Build minimal Eth/IPv4/TCP packet
    const pkt = new Uint8Array(14 + 20 + 20); // eth + ip + tcp minimum
    // Ethernet
    pkt.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0); // dst mac
    pkt.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6); // src mac
    pkt[12] = 0x08; pkt[13] = 0x00; // IPv4
    // IPv4
    pkt[14] = 0x45; // v4, ihl=5
    pkt[16] = 0x00; pkt[17] = 40; // total length = 40 (20+20)
    pkt[14 + 8] = 64; // TTL
    pkt[14 + 9] = 6; // TCP
    pkt.set([10, 0, 0, 1], 14 + 12); // src ip
    pkt.set([192, 168, 1, 1], 14 + 16); // dst ip
    // TCP
    const tcpOff = 34;
    pkt[tcpOff] = 0x1f; pkt[tcpOff + 1] = 0x90; // src port 8080
    pkt[tcpOff + 2] = 0x00; pkt[tcpOff + 3] = 0x50; // dst port 80
    pkt[tcpOff + 12] = 0x50; // data offset = 5*4=20

    const packets = [{
      packetNumber: 0,
      timestamp: { ticks: 0n, unitsPerSecond: 1000000n, offsetSeconds: 0n },
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: 0,
      data: pkt,
    }];

    const result = analyzePackets(packets);

    expect(result.totalPackets).toBe(1);
    expect(result.decodedPackets).toBe(1);
    expect(result.histogram.counts.get('ethernet')).toBe(1);
    expect(result.histogram.counts.get('ipv4')).toBe(1);
    expect(result.histogram.counts.get('tcp')).toBe(1);

    // Entities
    const ips = result.entities.filter(e => e.category === 'ipv4');
    expect(ips.length).toBe(2);
    expect(ips.some(e => e.value === '10.0.0.1')).toBe(true);
    expect(ips.some(e => e.value === '192.168.1.1')).toBe(true);

    const macs = result.entities.filter(e => e.category === 'mac');
    expect(macs.length).toBe(2);

    const ports = result.entities.filter(e => e.category === 'port');
    expect(ports.some(e => e.value === 'tcp/8080')).toBe(true);
    expect(ports.some(e => e.value === 'tcp/80')).toBe(true);
  });

  it('decodes Ethernet/IPv6/UDP packet', () => {
    const pkt = new Uint8Array(14 + 40 + 8);
    // Ethernet
    pkt.set([0x33, 0x33, 0x00, 0x00, 0x00, 0x01], 0);
    pkt.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 6);
    pkt[12] = 0x86; pkt[13] = 0xdd; // IPv6
    // IPv6
    pkt[14] = 0x60; // version 6
    pkt[14 + 4] = 0; pkt[14 + 5] = 8; // payload length = 8 (UDP header only)
    pkt[14 + 6] = 17; // next header = UDP
    pkt[14 + 7] = 64; // hop limit
    // src: fe80::1
    pkt[14 + 8] = 0xfe; pkt[14 + 9] = 0x80; pkt[14 + 23] = 0x01;
    // dst: ff02::1
    pkt[14 + 24] = 0xff; pkt[14 + 25] = 0x02; pkt[14 + 39] = 0x01;
    // UDP
    const udpOff = 14 + 40;
    pkt[udpOff] = 0x14; pkt[udpOff + 1] = 0xe9; // src 5353
    pkt[udpOff + 2] = 0x14; pkt[udpOff + 3] = 0xe9; // dst 5353
    pkt[udpOff + 4] = 0x00; pkt[udpOff + 5] = 8; // length

    const packets = [{
      packetNumber: 0,
      timestamp: { ticks: 0n, unitsPerSecond: 1000000n, offsetSeconds: 0n },
      capturedLength: pkt.length, originalLength: pkt.length,
      linkType: 1, interfaceId: 0, sectionIndex: 0, fileOffset: 0, data: pkt,
    }];

    const result = analyzePackets(packets);
    expect(result.histogram.counts.get('ipv6')).toBe(1);
    expect(result.histogram.counts.get('udp')).toBe(1);
    expect(result.entities.some(e => e.category === 'ipv6')).toBe(true);
  });

  it('decodes ARP packet', () => {
    const pkt = new Uint8Array(14 + 28);
    pkt.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
    pkt.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 6);
    pkt[12] = 0x08; pkt[13] = 0x06; // ARP
    // ARP
    const a = 14;
    pkt[a] = 0x00; pkt[a + 1] = 0x01; // hw ethernet
    pkt[a + 2] = 0x08; pkt[a + 3] = 0x00; // proto ipv4
    pkt[a + 4] = 6; pkt[a + 5] = 4; // hw/proto len
    pkt[a + 6] = 0x00; pkt[a + 7] = 0x01; // request
    pkt.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], a + 8); // sender mac
    pkt.set([10, 0, 0, 1], a + 14); // sender ip
    pkt.set([0x00, 0x00, 0x00, 0x00, 0x00, 0x00], a + 18); // target mac
    pkt.set([10, 0, 0, 2], a + 24); // target ip

    const packets = [{
      packetNumber: 0,
      timestamp: { ticks: 0n, unitsPerSecond: 1000000n, offsetSeconds: 0n },
      capturedLength: pkt.length, originalLength: pkt.length,
      linkType: 1, interfaceId: 0, sectionIndex: 0, fileOffset: 0, data: pkt,
    }];

    const result = analyzePackets(packets);
    expect(result.histogram.counts.get('arp')).toBe(1);
    expect(result.entities.some(e => e.value === '10.0.0.1')).toBe(true);
    expect(result.entities.some(e => e.value === '10.0.0.2')).toBe(true);
  });

  it('marks non-Ethernet/IPv4 ARP as unsupported (Krok 3)', () => {
    // hwLen=1/protoLen=0 (e.g. some exotic hw type) — not the Ethernet/IPv4 shape
    // this decoder understands. Must surface an explicit issue, not silently
    // report a clean "arp" packet with no address fields.
    const pkt = new Uint8Array(14 + 28); // probe() requires >= 28 bytes of ARP data
    pkt.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
    pkt.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 6);
    pkt[12] = 0x08; pkt[13] = 0x06; // ARP
    const a = 14;
    pkt[a] = 0x00; pkt[a + 1] = 0x18; // hw type 24 (some exotic type)
    pkt[a + 2] = 0x08; pkt[a + 3] = 0x00; // proto ipv4
    pkt[a + 4] = 1; pkt[a + 5] = 0; // hwLen=1, protoLen=0 (not 6/4)
    pkt[a + 6] = 0x00; pkt[a + 7] = 0x01; // request

    const packets = [{
      packetNumber: 0,
      timestamp: { ticks: 0n, unitsPerSecond: 1000000n, offsetSeconds: 0n },
      capturedLength: pkt.length, originalLength: pkt.length,
      linkType: 1, interfaceId: 0, sectionIndex: 0, fileOffset: 0, data: pkt,
    }];

    const result = analyzePackets(packets);
    expect(result.histogram.counts.get('arp')).toBe(1);
    const summary = result.summaries[0]!;
    expect(summary.issues.some(i => i === 'unsupported-arp-hwtype:1/0')).toBe(true);
    expect(summary.hasUnsupported).toBe(true);
  });

  it('marks unsupported link type', () => {
    const packets = [{
      packetNumber: 0,
      timestamp: { ticks: 0n, unitsPerSecond: 1000000n, offsetSeconds: 0n },
      capturedLength: 20, originalLength: 20,
      linkType: 999, interfaceId: 0, sectionIndex: 0, fileOffset: 0,
      data: new Uint8Array(20),
    }];

    const result = analyzePackets(packets);
    expect(result.unsupportedLinkTypes.has(999)).toBe(true);
    expect(result.summaries[0]!.hasUnsupported).toBe(true);
  });

  it('detects IPv4 fragments', () => {
    const pkt = new Uint8Array(14 + 20 + 8);
    pkt.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
    pkt.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
    pkt[12] = 0x08; pkt[13] = 0x00;
    pkt[14] = 0x45;
    pkt[16] = 0x00; pkt[17] = 28;
    pkt[14 + 6] = 0x20; pkt[14 + 7] = 0x00; // MF=1, offset=0
    pkt[14 + 9] = 17; // UDP
    pkt.set([10, 0, 0, 1], 14 + 12);
    pkt.set([10, 0, 0, 2], 14 + 16);

    const packets = [{
      packetNumber: 0,
      timestamp: { ticks: 0n, unitsPerSecond: 1000000n, offsetSeconds: 0n },
      capturedLength: pkt.length, originalLength: pkt.length,
      linkType: 1, interfaceId: 0, sectionIndex: 0, fileOffset: 0, data: pkt,
    }];

    const result = analyzePackets(packets);
    expect(result.summaries[0]!.issues).toContain('fragment');
  });

  it('decodes Ethernet/IPv4/IP-in-IP/IPv4/TCP (Krok 2 — tunnel registration)', () => {
    // Outer eth(14) + outer ipv4(20, proto=4) + inner ipv4(20, proto=6) + tcp(20)
    const pkt = new Uint8Array(14 + 20 + 20 + 20);
    pkt.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
    pkt.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
    pkt[12] = 0x08; pkt[13] = 0x00; // IPv4

    const outer = 14;
    pkt[outer] = 0x45;
    pkt[outer + 2] = 0x00; pkt[outer + 3] = 60; // total length = 20+20+20
    pkt[outer + 9] = 4; // IP-in-IP
    pkt.set([203, 0, 113, 1], outer + 12); // outer src (public)
    pkt.set([203, 0, 113, 2], outer + 16); // outer dst (public)

    const inner = outer + 20;
    pkt[inner] = 0x45;
    pkt[inner + 2] = 0x00; pkt[inner + 3] = 40; // total length = 20+20
    pkt[inner + 9] = 6; // TCP
    pkt.set([10, 0, 0, 1], inner + 12); // inner src (private)
    pkt.set([10, 0, 0, 2], inner + 16); // inner dst (private)

    const tcpOff = inner + 20;
    pkt[tcpOff] = 0x1f; pkt[tcpOff + 1] = 0x90; // src port 8080
    pkt[tcpOff + 2] = 0x00; pkt[tcpOff + 3] = 0x50; // dst port 80
    pkt[tcpOff + 12] = 0x50; // data offset = 20

    const packets = [{
      packetNumber: 0,
      timestamp: { ticks: 0n, unitsPerSecond: 1000000n, offsetSeconds: 0n },
      capturedLength: pkt.length, originalLength: pkt.length,
      linkType: 1, interfaceId: 0, sectionIndex: 0, fileOffset: 0, data: pkt,
    }];

    const result = analyzePackets(packets);
    expect(result.histogram.counts.get('ipv4')).toBe(1);
    expect(result.histogram.counts.get('ipip-ipv4')).toBe(1);

    // Per Krok 2 design: inner IP addresses ARE collected, inner transport is not decoded
    // (matches sanitize/tunnel.ts's scope) and is explicitly flagged, not silently dropped.
    const ips = result.entities.filter(e => e.category === 'ipv4').map(e => e.value);
    expect(ips).toEqual(expect.arrayContaining(['203.0.113.1', '203.0.113.2', '10.0.0.1', '10.0.0.2']));
    expect(result.summaries[0]!.issues.some(i => i === 'unsupported-tunnel-transport:6')).toBe(true);
    expect(result.entities.filter(e => e.category === 'port').length).toBe(0);
  });

  it('decodes Ethernet/IPv4/GRE/IPv4/UDP (Krok 2 — tunnel registration)', () => {
    // Outer eth(14) + outer ipv4(20, proto=47 GRE) + GRE(4) + inner ipv4(20, proto=17 UDP) + udp(8)
    const pkt = new Uint8Array(14 + 20 + 4 + 20 + 8);
    pkt.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
    pkt.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
    pkt[12] = 0x08; pkt[13] = 0x00;

    const outer = 14;
    pkt[outer] = 0x45;
    pkt[outer + 2] = 0x00; pkt[outer + 3] = 52; // total length = 4+20+8+20
    pkt[outer + 9] = 47; // GRE
    pkt.set([203, 0, 113, 10], outer + 12);
    pkt.set([203, 0, 113, 20], outer + 16);

    const greOff = outer + 20;
    pkt[greOff] = 0x00; pkt[greOff + 1] = 0x00; // flags = 0 (no checksum/key/seq)
    pkt[greOff + 2] = 0x08; pkt[greOff + 3] = 0x00; // protocol = IPv4

    const inner = greOff + 4;
    pkt[inner] = 0x45;
    pkt[inner + 2] = 0x00; pkt[inner + 3] = 28; // total length = 20+8
    pkt[inner + 9] = 17; // UDP
    pkt.set([172, 16, 0, 1], inner + 12);
    pkt.set([172, 16, 0, 2], inner + 16);

    const udpOff = inner + 20;
    pkt[udpOff] = 0x00; pkt[udpOff + 1] = 53; // src port 53
    pkt[udpOff + 2] = 0x00; pkt[udpOff + 3] = 53; // dst port 53
    pkt[udpOff + 4] = 0x00; pkt[udpOff + 5] = 8; // length

    const packets = [{
      packetNumber: 0,
      timestamp: { ticks: 0n, unitsPerSecond: 1000000n, offsetSeconds: 0n },
      capturedLength: pkt.length, originalLength: pkt.length,
      linkType: 1, interfaceId: 0, sectionIndex: 0, fileOffset: 0, data: pkt,
    }];

    const result = analyzePackets(packets);
    expect(result.histogram.counts.get('gre')).toBe(1);
    // Per Krok 2 design: GRE's inner payload IS decoded when it's an IP-in-IP/IPv6-in-IP
    // tunnel layer, matching sanitize/tunnel.ts's own recursive decodeGre behavior.
    expect(result.histogram.counts.get('ipip-ipv4')).toBe(1);
    const ips = result.entities.filter(e => e.category === 'ipv4').map(e => e.value);
    expect(ips).toEqual(expect.arrayContaining(['203.0.113.10', '203.0.113.20', '172.16.0.1', '172.16.0.2']));
    expect(result.summaries[0]!.issues.some(i => i === 'unsupported-tunnel-transport:17')).toBe(true);
  });

  it('decodes Ethernet/IPv4/UDP(4789)/VXLAN/inner-Ethernet/IPv4/UDP (Krok 2 — VXLAN registration)', () => {
    // Outer eth(14) + outer ipv4(20) + outer udp(8, dst=4789) + vxlan(8) + inner eth(14) +
    // inner ipv4(20) + inner udp(8)
    const pkt = new Uint8Array(14 + 20 + 8 + 8 + 14 + 20 + 8);
    pkt.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
    pkt.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
    pkt[12] = 0x08; pkt[13] = 0x00;

    const outerIp = 14;
    pkt[outerIp] = 0x45;
    const outerTotalLen = 20 + 8 + 8 + 14 + 20 + 8; // ipv4 header + everything after
    pkt[outerIp + 2] = (outerTotalLen >> 8) & 0xff; pkt[outerIp + 3] = outerTotalLen & 0xff;
    pkt[outerIp + 9] = 17; // UDP
    pkt.set([203, 0, 113, 30], outerIp + 12);
    pkt.set([203, 0, 113, 40], outerIp + 16);

    const outerUdp = outerIp + 20;
    pkt[outerUdp] = 0xc0; pkt[outerUdp + 1] = 0x00; // src port ephemeral
    pkt[outerUdp + 2] = 0x12; pkt[outerUdp + 3] = 0xb5; // dst port 4789
    const udpLen = 8 + 8 + 14 + 20 + 8;
    pkt[outerUdp + 4] = (udpLen >> 8) & 0xff; pkt[outerUdp + 5] = udpLen & 0xff;

    const vxlanOff = outerUdp + 8;
    pkt[vxlanOff] = 0x08; // I flag set
    pkt[vxlanOff + 4] = 0x00; pkt[vxlanOff + 5] = 0x00; pkt[vxlanOff + 6] = 0x2a; // VNI = 42

    const innerEth = vxlanOff + 8;
    pkt.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], innerEth); // inner dst mac
    pkt.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], innerEth + 6); // inner src mac
    pkt[innerEth + 12] = 0x08; pkt[innerEth + 13] = 0x00; // inner IPv4

    const innerIp = innerEth + 14;
    pkt[innerIp] = 0x45;
    pkt[innerIp + 2] = 0x00; pkt[innerIp + 3] = 28; // total length = 20+8
    pkt[innerIp + 9] = 17; // UDP
    pkt.set([192, 168, 50, 1], innerIp + 12);
    pkt.set([192, 168, 50, 2], innerIp + 16);

    const innerUdp = innerIp + 20;
    pkt[innerUdp] = 0x00; pkt[innerUdp + 1] = 53;
    pkt[innerUdp + 2] = 0x00; pkt[innerUdp + 3] = 53;
    pkt[innerUdp + 4] = 0x00; pkt[innerUdp + 5] = 8;

    const packets = [{
      packetNumber: 0,
      timestamp: { ticks: 0n, unitsPerSecond: 1000000n, offsetSeconds: 0n },
      capturedLength: pkt.length, originalLength: pkt.length,
      linkType: 1, interfaceId: 0, sectionIndex: 0, fileOffset: 0, data: pkt,
    }];

    const result = analyzePackets(packets);
    expect(result.histogram.counts.get('vxlan')).toBe(1);
    expect(result.histogram.counts.get('ipip-ipv4')).toBe(1);

    const macs = result.entities.filter(e => e.category === 'mac').map(e => e.value);
    expect(macs).toEqual(expect.arrayContaining(['02:00:00:00:00:01', '02:00:00:00:00:02']));
    const ips = result.entities.filter(e => e.category === 'ipv4').map(e => e.value);
    expect(ips).toEqual(expect.arrayContaining(['192.168.50.1', '192.168.50.2']));
  });

  it('bounds nested tunnel recursion at MAX_DECODE_DEPTH without crashing (Krok 2)', () => {
    // Build outer IPv4(proto=4) wrapping 3 more nested IPv4(proto=4) layers, the last of
    // which points to a 5th "IP-in-IP" layer that must never actually be parsed — it should
    // stop as `unsupported-ipproto:4` once the depth budget (4) is exhausted, not crash or
    // recurse forever.
    let payload = new Uint8Array(20).fill(0xaa); // never actually parsed as IPv4
    for (let i = 0; i < 4; i++) {
      const layer = new Uint8Array(20 + payload.length);
      layer[0] = 0x45;
      const totalLen = layer.length;
      layer[2] = (totalLen >> 8) & 0xff; layer[3] = totalLen & 0xff;
      layer[9] = 4; // IP-in-IP, every layer nests another one
      layer.set([10, 0, 0, i + 1], 12);
      layer.set([10, 0, 0, i + 101], 16);
      layer.set(payload, 20);
      payload = layer;
    }

    const pkt = new Uint8Array(14 + payload.length);
    pkt.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
    pkt.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
    pkt[12] = 0x08; pkt[13] = 0x00;
    pkt.set(payload, 14);

    const packets = [{
      packetNumber: 0,
      timestamp: { ticks: 0n, unitsPerSecond: 1000000n, offsetSeconds: 0n },
      capturedLength: pkt.length, originalLength: pkt.length,
      linkType: 1, interfaceId: 0, sectionIndex: 0, fileOffset: 0, data: pkt,
    }];

    expect(() => analyzePackets(packets)).not.toThrow();
    const result = analyzePackets(packets);
    // Outer ipv4 (via EtherType) + 3 nested ipip-ipv4 layers decode successfully (4 IPv4
    // headers total, 8 addresses); the 4th nesting attempt is refused by the depth budget.
    expect(result.histogram.counts.get('ipv4')).toBe(1);
    expect(result.histogram.counts.get('ipip-ipv4')).toBe(3);
    expect(result.summaries[0]!.issues.some(i => i === 'unsupported-ipproto:4')).toBe(true);
  });
});

describe('Protocol analysis on real captures', () => {
  const realFiles = [
    { name: 'app-crash-2.pcap', expectedPackets: 13010 },
    { name: 'dt.pcap', expectedPackets: 4393 },
  ];

  for (const { name, expectedPackets } of realFiles) {
    const filePath = join(SQUELCH_DIR, '..', name);
    const fileExists = existsSync(filePath);

    it(`analyzes ${name} with stable counts`, { skip: !fileExists }, () => {
      const raw = readFileSync(filePath);
      const buffer = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength);
      const { packets } = readClassicPcap(buffer);
      expect(packets.length).toBe(expectedPackets);

      const result = analyzePackets(packets);
      expect(result.totalPackets).toBe(expectedPackets);
      expect(result.decodedPackets).toBeGreaterThan(0);
      expect(result.decodedPackets).toBe(expectedPackets); // all Ethernet

      // Must have IPv4 entities
      expect(result.entities.some(e => e.category === 'ipv4')).toBe(true);
      expect(result.entities.some(e => e.category === 'mac')).toBe(true);

      // Histogram must have ethernet
      expect(result.histogram.counts.get('ethernet')).toBe(expectedPackets);
      expect(result.histogram.counts.has('ipv4') || result.histogram.counts.has('ipv6') || result.histogram.counts.has('arp')).toBe(true);

      // Unsupported link types must be empty (both are Ethernet)
      expect(result.unsupportedLinkTypes.size).toBe(0);
    });

    it(`paging works for ${name}`, { skip: !fileExists }, () => {
      const raw = readFileSync(filePath);
      const buffer = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength);
      const { packets } = readClassicPcap(buffer);
      const result = analyzePackets(packets);

      const page = getPacketPage(result.summaries, 100, 50);
      expect(page.length).toBe(50);
      expect(page[0]!.packetNumber).toBe(100);
    });
  }
});
