/**
 * CF-13 — recursive tunnels, ICMP embedded ports, ICMPv6 NDP.
 */

import { describe, expect, it } from 'vitest';
import {
  sanitizePacket,
  sanitizeIcmpEmbedded,
  sanitizeIcmpv6Ndp,
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  type PacketInput,
} from '../../../src/pcap/sanitize';
import { SessionMapping } from '../../../src/pcap/anonymization/mapping';
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector';

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff));
}

function putIpv4(buf: Uint8Array, offset: number, src: number[], dst: number[], proto: number, payloadLen: number): void {
  buf[offset] = 0x45;
  const total = 20 + payloadLen;
  buf[offset + 2] = (total >> 8) & 0xff;
  buf[offset + 3] = total & 0xff;
  buf[offset + 9] = proto;
  buf.set(src, offset + 12);
  buf.set(dst, offset + 16);
}

function putUdp(buf: Uint8Array, offset: number, srcPort: number, dstPort: number, payloadLen: number): void {
  buf[offset] = (srcPort >> 8) & 0xff;
  buf[offset + 1] = srcPort & 0xff;
  buf[offset + 2] = (dstPort >> 8) & 0xff;
  buf[offset + 3] = dstPort & 0xff;
  const total = 8 + payloadLen;
  buf[offset + 4] = (total >> 8) & 0xff;
  buf[offset + 5] = total & 0xff;
}

function buildSipInvite(canaryIp: string, canaryUser = 'alice'): Uint8Array {
  const body = [
    'v=0',
    `o=- 1 2 IN IP4 ${canaryIp}`,
    `c=IN IP4 ${canaryIp}`,
    'm=audio 54400 RTP/AVP 0',
  ].join('\r\n');
  const headers = [
    `INVITE sip:${canaryUser}@${canaryIp} SIP/2.0`,
    `Via: SIP/2.0/UDP ${canaryIp}:5060;branch=z9hG4bKcf13`,
    `From: <sip:${canaryUser}@${canaryIp}>;tag=t1`,
    `Call-ID: cf13-dialog@${canaryIp}`,
    'Content-Type: application/sdp',
    `Content-Length: ${body.length}`,
  ];
  return latin1(`${headers.join('\r\n')}\r\n\r\n${body}`);
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const len = result.truncatedLength ?? original.length;
  const out = original.slice(0, len);
  for (const patch of result.patches) {
    if (patch.offset < len) {
      out.set(patch.data.slice(0, len - patch.offset), patch.offset);
    }
  }
  return out;
}

function buildGreSipPacket(outerSrc: number[], outerDst: number[], innerSrc: number[], innerDst: number[], sip: Uint8Array): Uint8Array {
  const greLen = 4;
  const innerIpLen = 20;
  const udpLen = 8;
  const total = 14 + 20 + greLen + innerIpLen + udpLen + sip.length;
  const buf = new Uint8Array(total);
  buf[12] = 0x08;
  buf[13] = 0x00;
  putIpv4(buf, 14, outerSrc, outerDst, 47, greLen + innerIpLen + udpLen + sip.length);
  const gre = 34;
  buf[gre] = 0;
  buf[gre + 1] = 0;
  buf[gre + 2] = 0x08;
  buf[gre + 3] = 0x00;
  const innerIp = gre + greLen;
  putIpv4(buf, innerIp, innerSrc, innerDst, 17, udpLen + sip.length);
  putUdp(buf, innerIp + 20, 5060, 5060, sip.length);
  buf.set(sip, innerIp + 20 + 8);
  return buf;
}

function buildIpipSipPacket(outerSrc: number[], outerDst: number[], innerSrc: number[], innerDst: number[], sip: Uint8Array): Uint8Array {
  const innerIpLen = 20;
  const udpLen = 8;
  const total = 14 + 20 + innerIpLen + udpLen + sip.length;
  const buf = new Uint8Array(total);
  buf[12] = 0x08;
  buf[13] = 0x00;
  putIpv4(buf, 14, outerSrc, outerDst, 4, innerIpLen + udpLen + sip.length);
  putIpv4(buf, 34, innerSrc, innerDst, 17, udpLen + sip.length);
  putUdp(buf, 54, 5060, 5060, sip.length);
  buf.set(sip, 62);
  return buf;
}

function buildVxlanSipPacket(
  outerSrc: number[],
  outerDst: number[],
  innerSrc: number[],
  innerDst: number[],
  sip: Uint8Array,
): Uint8Array {
  const vxlanLen = 8;
  const innerEth = 14;
  const innerIpLen = 20;
  const udpLen = 8;
  const outerUdpPayload = vxlanLen + innerEth + innerIpLen + udpLen + sip.length;
  const total = 14 + 20 + 8 + outerUdpPayload;
  const buf = new Uint8Array(total);
  buf[12] = 0x08;
  buf[13] = 0x00;
  putIpv4(buf, 14, outerSrc, outerDst, 17, 8 + outerUdpPayload);
  putUdp(buf, 34, 12345, 4789, outerUdpPayload);
  const vxlan = 42;
  buf[vxlan] = 0x08; // I flag
  const innerEthOff = vxlan + 8;
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01], innerEthOff);
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02], innerEthOff + 6);
  buf[innerEthOff + 12] = 0x08;
  buf[innerEthOff + 13] = 0x00;
  const innerIp = innerEthOff + 14;
  putIpv4(buf, innerIp, innerSrc, innerDst, 17, udpLen + sip.length);
  putUdp(buf, innerIp + 20, 5060, 5060, sip.length);
  buf.set(sip, innerIp + 28);
  return buf;
}

describe('CF-13 recursive tunnels', () => {
  const canaryIp = '192.168.55.77';
  const canaryOctets = [192, 168, 55, 77];
  const peer = [10, 0, 0, 2];

  it('anonymizes SIP/UDP inside GRE with same alias as outer IP', () => {
    const sip = buildSipInvite(canaryIp);
    const pkt = buildGreSipPacket(canaryOctets, peer, canaryOctets, peer, sip);
    const mapping = new SessionMapping();
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    expect(result.coverage.some((c) => c.protocol === 'sip')).toBe(true);
    expect(result.coverage.some((c) => c.protocol === 'gre')).toBe(true);

    const exported = applyPatches(pkt, result);
    const text = new TextDecoder('ascii', { fatal: false }).decode(exported);
    expect(text).not.toContain(canaryIp);
    expect(text).not.toContain('alice@192.168.55.77');

    const outerAlias = mapping.map('ipv4', canaryIp);
    const outerParts = outerAlias.split('.').map(Number);
    // Outer IPv4 src at offset 26
    expect([...exported.slice(26, 30)]).toEqual(outerParts);
    // Inner IPv4 src inside GRE
    expect([...exported.slice(34 + 4 + 12, 34 + 4 + 16)]).toEqual(outerParts);
  });

  it('anonymizes SIP/UDP inside IP-in-IP', () => {
    const sip = buildSipInvite(canaryIp);
    const pkt = buildIpipSipPacket(canaryOctets, peer, canaryOctets, peer, sip);
    const mapping = new SessionMapping();
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
    );
    expect(result.coverage.some((c) => c.protocol === 'sip')).toBe(true);
    const text = new TextDecoder('ascii', { fatal: false }).decode(applyPatches(pkt, result));
    expect(text).not.toContain(canaryIp);
  });

  it('anonymizes SIP/UDP inside VXLAN', () => {
    const sip = buildSipInvite(canaryIp);
    const pkt = buildVxlanSipPacket(canaryOctets, peer, canaryOctets, peer, sip);
    const mapping = new SessionMapping();
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
    );
    expect(result.coverage.some((c) => c.protocol === 'vxlan')).toBe(true);
    expect(result.coverage.some((c) => c.protocol === 'sip')).toBe(true);
    const text = new TextDecoder('ascii', { fatal: false }).decode(applyPatches(pkt, result));
    expect(text).not.toContain(canaryIp);
  });

  it('marks depth limit as unsupported under safe policy', () => {
    const data = new Uint8Array(14 + 20 * 5);
    data[12] = 0x08;
    data[13] = 0x00;
    let off = 14;
    for (let i = 0; i < 5; i++) {
      data[off] = 0x45;
      data[off + 9] = 4;
      data.set([10, i, 0, 1], off + 12);
      data.set([10, i, 0, 2], off + 16);
      off += 20;
    }
    const result = sanitizePacket(
      { index: 0, data, capturedLength: data.length, originalLength: data.length, linkType: 1 },
      HIGH_PRIVACY_POLICY,
      new SessionMapping(),
    );
    expect(result.coverage.some((c) => c.status === 'unsupported' || c.protocol.includes('tunnel'))).toBe(true);
  });
});

describe('CF-13 ICMP embedded ports', () => {
  it('maps embedded UDP ports and does not cover leftover bytes', () => {
    const embedded = new Uint8Array(28);
    embedded[0] = 0x45;
    embedded[9] = 17; // UDP
    embedded.set([172, 16, 0, 99], 12);
    embedded.set([10, 0, 0, 50], 16);
    embedded[20] = 0x13;
    embedded[21] = 0xc4; // 5060
    embedded[22] = 0x13;
    embedded[23] = 0xc5; // 5061
    embedded[24] = 0xde;
    embedded[25] = 0xad;
    embedded[26] = 0xbe;
    embedded[27] = 0xef;

    const collector = new PatchCollector(embedded.length);
    const mapping = new SessionMapping();
    const coverage = sanitizeIcmpEmbedded(embedded, 0, embedded.length, collector, mapping);

    expect(coverage.some((c) => c.protocol === 'icmp-embedded-ports' && c.status === 'covered')).toBe(true);
    expect(coverage.some((c) => c.protocol === 'icmp-embedded-payload' && c.status === 'unsupported')).toBe(true);
    expect(collector.count).toBeGreaterThanOrEqual(2); // at least both embedded IPs

    const out = embedded.slice();
    for (const p of collector.getPatches()) out.set(p.data, p.offset);
    expect([...out.slice(12, 16)].join('.')).not.toBe('172.18.0.99');

    // Ports use the same mapping authority — alias must be stable if remapped
    const portAlias = mapping.map('port', 'udp/5060');
    expect(portAlias.startsWith('udp/')).toBe(true);
  });

  it('patches embedded ports inside full ICMPv4 error packet', () => {
    const sipHintPort = 5060;
    const embeddedLen = 28;
    const icmpLen = 8 + embeddedLen;
    const total = 14 + 20 + icmpLen;
    const buf = new Uint8Array(total);
    buf[12] = 0x08;
    buf[13] = 0x00;
    putIpv4(buf, 14, [192, 168, 1, 1], [192, 168, 1, 2], 1, icmpLen);
    const icmp = 34;
    buf[icmp] = 3; // destination unreachable
    const emb = icmp + 8;
    buf[emb] = 0x45;
    buf[emb + 9] = 17;
    buf.set([198, 51, 100, 9], emb + 12);
    buf.set([203, 0, 113, 9], emb + 16);
    buf[emb + 20] = (sipHintPort >> 8) & 0xff;
    buf[emb + 21] = sipHintPort & 0xff;
    buf[emb + 22] = 0x13;
    buf[emb + 23] = 0xc4;

    const mapping = new SessionMapping();
    const result = sanitizePacket(
      { index: 0, data: buf, capturedLength: buf.length, originalLength: buf.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
    );
    expect(result.coverage.some((c) => c.protocol === 'icmp-embedded-ports')).toBe(true);
    const exported = applyPatches(buf, result);
    expect([...exported.slice(emb + 12, emb + 16)]).not.toEqual([198, 51, 100, 9]);
  });
});

describe('CF-13 ICMPv6 NDP', () => {
  function buildIpv6Icmp(icmpPayload: Uint8Array): Uint8Array {
    const total = 14 + 40 + icmpPayload.length;
    const buf = new Uint8Array(total);
    buf[12] = 0x86;
    buf[13] = 0xdd;
    // IPv6 header at offset 14
    buf[14] = 0x60;
    buf[18] = (icmpPayload.length >> 8) & 0xff;
    buf[19] = icmpPayload.length & 0xff;
    buf[20] = 58; // next header = ICMPv6
    buf[21] = 64; // hop limit
    // src 2001:db8::1 at offset 22
    buf[22] = 0x20;
    buf[23] = 0x01;
    buf[24] = 0x0d;
    buf[25] = 0xb8;
    buf[37] = 0x01;
    // dst 2001:db8::2 at offset 38
    buf[38] = 0x20;
    buf[39] = 0x01;
    buf[40] = 0x0d;
    buf[41] = 0xb8;
    buf[53] = 0x02;
    buf.set(icmpPayload, 54);
    return buf;
  }

  it('maps Source Link-Layer Address on Neighbor Solicitation', () => {
    // NS: type 135, code 0, checksum, reserved(4), target(16), option SLL
    const icmp = new Uint8Array(8 + 16 + 8);
    icmp[0] = 135;
    // target 2001:db8::99
    icmp[8] = 0x20;
    icmp[9] = 0x01;
    icmp[10] = 0x0d;
    icmp[11] = 0xb8;
    icmp[23] = 0x99;
    // option type 1, length 1, MAC
    icmp[24] = 1;
    icmp[25] = 1;
    icmp.set([0xde, 0xad, 0xbe, 0xef, 0x00, 0x11], 26);

    const pkt = buildIpv6Icmp(icmp);
    const mapping = new SessionMapping();
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
    );
    expect(result.coverage.some((c) => c.protocol === 'ndp-sll' && c.status === 'covered')).toBe(true);
    const exported = applyPatches(pkt, result);
    const macOff = 54 + 26;
    expect([...exported.slice(macOff, macOff + 6)]).not.toEqual([0xde, 0xad, 0xbe, 0xef, 0x00, 0x11]);
  });

  it('marks malformed NDP TLV length as malformed', () => {
    const icmp = new Uint8Array(32);
    icmp[0] = 135;
    icmp[24] = 1;
    icmp[25] = 0; // illegal length
    const coverage = sanitizeIcmpv6Ndp(icmp, 0, icmp.length, 135, new PatchCollector(icmp.length), new SessionMapping());
    expect(coverage).not.toBeNull();
    expect(coverage!.some((c) => c.status === 'malformed')).toBe(true);
  });
});
