/**
 * H-2 — VRRP (IP proto 112): remap the embedded virtual IP(s), preserve version/type/VRID/
 * priority/count/interval/checksum, redact a cleartext auth password if present, and never
 * remap the IANA-reserved virtual-router MAC (00:00:5e:00:01:{VRID}).
 */

import { describe, expect, it } from 'vitest';
import { sanitizePacket, DIAGNOSTIC_POLICY, type PacketInput } from '../../../src/pcap/sanitize';
import { SessionMapping } from '../../../src/pcap/anonymization/mapping';

function applyExport(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const len = result.truncatedLength ?? original.length;
  const out = original.slice(0, len);
  for (const patch of result.patches) {
    if (patch.offset < len) out.set(patch.data.slice(0, len - patch.offset), patch.offset);
  }
  return out;
}

/** Ethernet + IPv4 (proto 112) + VRRPv2 advertisement, one virtual IP, no/simple auth. */
function buildVrrpV2Packet(opts: {
  srcMac?: number[];
  vrid: number;
  priority: number;
  virtualIp: number[];
  authType: number;
  authData?: number[];
}): Uint8Array {
  const srcMac = opts.srcMac ?? [0x00, 0x00, 0x5e, 0x00, 0x01, opts.vrid];
  const vrrpLen = 8 + 4 + 8; // header + 1 addr + auth trailer
  const total = 14 + 20 + vrrpLen;
  const buf = new Uint8Array(total);
  // Ethernet: dst = VRRP multicast MAC, src = virtual-router MAC
  buf.set([0x01, 0x00, 0x5e, 0x00, 0x00, 0x12], 0);
  buf.set(srcMac, 6);
  buf[12] = 0x08;
  buf[13] = 0x00;
  // IPv4
  const ipOff = 14;
  buf[ipOff] = 0x45;
  buf[ipOff + 2] = (20 + vrrpLen) >> 8;
  buf[ipOff + 3] = (20 + vrrpLen) & 0xff;
  buf[ipOff + 9] = 112; // VRRP
  buf.set([192, 168, 1, 1], ipOff + 12);
  buf.set([224, 0, 0, 18], ipOff + 16);
  // VRRP
  const vOff = ipOff + 20;
  buf[vOff] = (2 << 4) | 1; // version 2, type 1 (advertisement)
  buf[vOff + 1] = opts.vrid;
  buf[vOff + 2] = opts.priority;
  buf[vOff + 3] = 1; // count IP addrs
  buf[vOff + 4] = opts.authType;
  buf[vOff + 5] = 1; // advertisement interval
  buf[vOff + 6] = 0xaa; // checksum (not recomputed by the sanitizer — structural passthrough)
  buf[vOff + 7] = 0xbb;
  buf.set(opts.virtualIp, vOff + 8);
  if (opts.authData) buf.set(opts.authData, vOff + 12);
  return buf;
}

describe('H-2 VRRP sanitizer', () => {
  it('remaps the virtual IP but preserves VRID/priority/count/interval/checksum bytes', () => {
    const pkt = buildVrrpV2Packet({ vrid: 7, priority: 100, virtualIp: [192, 168, 1, 254], authType: 0 });
    const mapping = new SessionMapping();
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    const exported = applyExport(pkt, result);

    const vOff = 14 + 20;
    // structural fields unchanged
    expect(exported[vOff]).toBe((2 << 4) | 1);
    expect(exported[vOff + 1]).toBe(7); // VRID
    expect(exported[vOff + 2]).toBe(100); // priority
    expect(exported[vOff + 3]).toBe(1); // count
    expect(exported[vOff + 4]).toBe(0); // auth type
    expect(exported[vOff + 5]).toBe(1); // interval
    expect(exported[vOff + 6]).toBe(0xaa);
    expect(exported[vOff + 7]).toBe(0xbb);
    // virtual IP remapped, no longer the original
    const mappedIp = Array.from(exported.slice(vOff + 8, vOff + 12));
    expect(mappedIp).not.toEqual([192, 168, 1, 254]);

    const coverageProtocols = result.coverage.map((c) => c.protocol);
    expect(coverageProtocols).toContain('vrrp');
    // The whole structural span must be closed off (covered), or export-boundary would
    // otherwise mask-in-place the "preserved" bytes right back out.
    const vrrpSpan = result.coverage.find((c) => c.protocol === 'vrrp');
    expect(vrrpSpan?.status).toBe('covered');
  });

  it('redacts a cleartext VRRP simple-text-authentication password (auth type 1)', () => {
    const password = [0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0, 0]; // "secret\0\0"
    const pkt = buildVrrpV2Packet({ vrid: 3, priority: 200, virtualIp: [10, 0, 0, 1], authType: 1, authData: password });
    const mapping = new SessionMapping();
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    const exported = applyExport(pkt, result);

    const vOff = 14 + 20;
    const authOffset = vOff + 12;
    const authBytes = Array.from(exported.slice(authOffset, authOffset + 8));
    expect(authBytes).not.toEqual(password);
    const authSpan = result.coverage.find((c) => c.protocol === 'vrrp-auth');
    expect(authSpan?.status).toBe('redacted');
  });

  it('never remaps the IANA-reserved VRRP virtual-router source MAC', () => {
    const pkt = buildVrrpV2Packet({ vrid: 9, priority: 50, virtualIp: [172, 16, 0, 1], authType: 0 });
    const mapping = new SessionMapping();
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    const exported = applyExport(pkt, result);

    const srcMac = Array.from(exported.slice(6, 12));
    expect(srcMac).toEqual([0x00, 0x00, 0x5e, 0x00, 0x01, 9]);
  });
});
