/**
 * H-3 — 802.3 LLC/SNAP detection: STP BPDUs (DSAP/SSAP 0x42) and CDP (SNAP OUI 00-00-0c,
 * PID 0x2000) must no longer fall through to full-packet mask-in-place. Only genuinely
 * identifying fields (bridge/root MAC, CDP device-id/VTP-domain) get changed; everything
 * else (timers, priorities, path cost, capabilities/platform/port-id strings) passes through.
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

function buildStpConfigBpdu(rootMac: number[], bridgeMac: number[]): Uint8Array {
  const bpdu = new Uint8Array(35);
  // ProtocolID=0, Version=0, Type=0 (config), Flags=0
  bpdu.set([0x80, 0x00], 5); // root priority
  bpdu.set(rootMac, 7);
  bpdu.set([0, 0, 0, 4], 13); // root path cost
  bpdu.set([0x80, 0x00], 17); // bridge priority
  bpdu.set(bridgeMac, 19);
  bpdu.set([0x80, 0x01], 25); // port id
  bpdu.set([0, 0], 27); // message age
  bpdu.set([0, 20], 29); // max age
  bpdu.set([0, 2], 31); // hello time
  bpdu.set([0, 15], 33); // forward delay

  const total = 6 + 6 + 2 + 3 + bpdu.length;
  const buf = new Uint8Array(total);
  buf.set([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00], 0); // STP multicast
  buf.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 6); // outer src MAC
  const len = 3 + bpdu.length;
  buf[12] = (len >> 8) & 0xff;
  buf[13] = len & 0xff;
  buf.set([0x42, 0x42, 0x03], 14); // LLC
  buf.set(bpdu, 17);
  return buf;
}

function buildMstpBpdu(rootMac: number[], bridgeMac: number[], cistBridgeMac: number[], configName: string): Uint8Array {
  const bpdu = new Uint8Array(35);
  bpdu[2] = 3; // Version 3 (MSTP)
  bpdu.set([0x80, 0x00], 5);
  bpdu.set(rootMac, 7);
  bpdu.set([0, 0, 0, 4], 13);
  bpdu.set([0x80, 0x00], 17);
  bpdu.set(bridgeMac, 19);
  bpdu.set([0x80, 0x01], 25);
  bpdu.set([0, 0], 27);
  bpdu.set([0, 20], 29);
  bpdu.set([0, 2], 31);
  bpdu.set([0, 15], 33);

  const V3_LEN = 64; // MCID(51) + CIST fixed(13), zero MSTI messages
  const mstp = new Uint8Array(3 + V3_LEN);
  mstp[0] = 0; // Version 1 Length
  mstp[1] = (V3_LEN >> 8) & 0xff;
  mstp[2] = V3_LEN & 0xff;
  // Format Selector at mstp[3] = 0
  const nameBytes = ascii(configName);
  mstp.set(nameBytes.slice(0, 32), 4); // Configuration Name (32 bytes, null-padded)
  // Revision Level (2) + Configuration Digest (16) left as zero.
  const cistOffset = 4 + 32 + 2 + 16; // = 54, relative to mstp start; root path cost bytes stay zero
  mstp.set([0x80, 0x00], cistOffset + 4); // CIST bridge priority
  mstp.set(cistBridgeMac, cistOffset + 6); // CIST bridge MAC

  const total = 6 + 6 + 2 + 3 + bpdu.length + mstp.length;
  const buf = new Uint8Array(total);
  buf.set([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00], 0);
  buf.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 6);
  const len = 3 + bpdu.length + mstp.length;
  buf[12] = (len >> 8) & 0xff;
  buf[13] = len & 0xff;
  buf.set([0x42, 0x42, 0x03], 14);
  buf.set(bpdu, 17);
  buf.set(mstp, 17 + bpdu.length);
  return buf;
}

function cdpTlv(type: number, value: number[]): number[] {
  const len = 4 + value.length;
  return [(type >> 8) & 0xff, type & 0xff, (len >> 8) & 0xff, len & 0xff, ...value];
}

function ascii(s: string): number[] {
  return Array.from(s, (c) => c.charCodeAt(0));
}

function buildCdpFrame(deviceId: string, mgmtIp: number[], nativeVlan?: number): Uint8Array {
  const addressValue = [
    0, 0, 0, 1, // 1 address
    1, 1, 0xcc, // protocol type=NLPID, len=1, protocol=IP
    0, 4, // address length
    ...mgmtIp,
  ];
  const tlvs = [
    ...cdpTlv(0x0001, ascii(deviceId)), // Device ID
    ...cdpTlv(0x0002, addressValue), // Addresses
    ...cdpTlv(0x0006, ascii('PLATFORM-X')), // Platform
    ...(nativeVlan !== undefined ? cdpTlv(0x000a, [(nativeVlan >> 8) & 0xff, nativeVlan & 0xff]) : []),
  ];
  const cdpBody = [0x02, 180, 0, 0, ...tlvs]; // version, ttl, checksum, tlvs

  const total = 6 + 6 + 2 + 8 + cdpBody.length;
  const buf = new Uint8Array(total);
  buf.set([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc], 0); // CDP multicast
  buf.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 6); // outer src MAC
  const len = 8 + cdpBody.length;
  buf[12] = (len >> 8) & 0xff;
  buf[13] = len & 0xff;
  buf.set([0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00], 14); // LLC + SNAP
  buf.set(cdpBody, 22);
  return buf;
}

describe('H-3 STP sanitizer', () => {
  it('remaps root/bridge MAC but preserves version/type/flags/cost/port/timers', () => {
    const rootMac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const bridgeMac = [0x12, 0x22, 0x33, 0x44, 0x55, 0x66]; // 0x12 LSB=0: unicast, not multicast
    const pkt = buildStpConfigBpdu(rootMac, bridgeMac);
    const mapping = new SessionMapping();
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    const exported = applyExport(pkt, result);

    const bpduOff = 17;
    // structural fields unchanged
    expect(Array.from(exported.slice(bpduOff, bpduOff + 5))).toEqual([0, 0, 0, 0, 0]); // protoId/version/type/flags
    expect(Array.from(exported.slice(bpduOff + 13, bpduOff + 17))).toEqual([0, 0, 0, 4]); // path cost
    expect(Array.from(exported.slice(bpduOff + 25, bpduOff + 35))).toEqual([0x80, 0x01, 0, 0, 0, 20, 0, 2, 0, 15]);
    // priorities preserved
    expect(Array.from(exported.slice(bpduOff + 5, bpduOff + 7))).toEqual([0x80, 0x00]);
    expect(Array.from(exported.slice(bpduOff + 17, bpduOff + 19))).toEqual([0x80, 0x00]);
    // MACs remapped
    expect(Array.from(exported.slice(bpduOff + 7, bpduOff + 13))).not.toEqual(rootMac);
    expect(Array.from(exported.slice(bpduOff + 19, bpduOff + 25))).not.toEqual(bridgeMac);

    const stpSpan = result.coverage.find((c) => c.protocol === 'stp');
    expect(stpSpan?.status).toBe('covered');
    expect(result.coverage.some((c) => c.protocol.startsWith('ether-0x'))).toBe(false);
  });

  it('MSTP: pseudonymizes the Configuration Name and CIST bridge MAC, preserves the digest/revision', () => {
    const rootMac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const bridgeMac = [0x12, 0x22, 0x33, 0x44, 0x55, 0x66];
    const cistBridgeMac = [0x14, 0x24, 0x34, 0x44, 0x54, 0x64];
    const pkt = buildMstpBpdu(rootMac, bridgeMac, cistBridgeMac, 'region-A');
    const mapping = new SessionMapping();
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    const exported = applyExport(pkt, result);
    const text = new TextDecoder('latin1').decode(exported);

    expect(text).not.toContain('region-A');
    expect(result.coverage.some((c) => c.protocol === 'stp-mstp-config-name')).toBe(true);

    const configNameOffset = 17 + 35 + 3 + 1; // BPDU start + classic header + v1/v3 len + format selector
    const configName = new TextDecoder('latin1').decode(exported.slice(configNameOffset, configNameOffset + 8));
    expect(configName).not.toBe('region-A');

    const cistMacOffset = configNameOffset + 32 + 2 + 16 + 4 + 2; // + revision + digest + root cost + priority
    expect(Array.from(exported.slice(cistMacOffset, cistMacOffset + 6))).not.toEqual(cistBridgeMac);

    // Revision Level (2 bytes, zero) and Configuration Digest (16 bytes, zero) preserved.
    const revisionOffset = configNameOffset + 32;
    expect(Array.from(exported.slice(revisionOffset, revisionOffset + 18))).toEqual(new Array(18).fill(0));
    expect(result.coverage.some((c) => c.protocol.startsWith('ether-0x'))).toBe(false);
  });
});

describe('H-3 CDP sanitizer', () => {
  it('redacts device-id, remaps embedded management IP, preserves platform TLV', () => {
    const pkt = buildCdpFrame('switch01.example.com', [10, 20, 30, 40]);
    const mapping = new SessionMapping();
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    const exported = applyExport(pkt, result);
    const text = new TextDecoder('latin1').decode(exported);

    expect(text).not.toContain('switch01.example.com');
    expect(text).toContain('PLATFORM-X');
    expect(Array.from(exported.slice(exported.length - 4))).not.toEqual([10, 20, 30, 40]);

    expect(result.coverage.some((c) => c.protocol === 'cdp')).toBe(true);
    expect(result.coverage.some((c) => c.protocol.startsWith('ether-0x'))).toBe(false);
    const identitySpan = result.coverage.find((c) => c.protocol === 'cdp-value' && c.status === 'redacted');
    expect(identitySpan).toBeDefined();
  });

  it('maps the Native VLAN TLV through the same VLAN mapping as the 802.1Q tag, never the raw ID', () => {
    const pkt = buildCdpFrame('switch01.example.com', [10, 20, 30, 40], 261);
    const mapping = new SessionMapping();
    const tagMapped = mapping.map('vlan', '261');
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    const exported = applyExport(pkt, result);

    const nativeVlanOffset = pkt.length - 2; // last TLV's 2-byte value, at the very end of the frame
    const exportedVlan = (exported[nativeVlanOffset]! << 8) | exported[nativeVlanOffset + 1]!;
    expect(exportedVlan).not.toBe(261);
    expect(exportedVlan).toBe(Number.parseInt(tagMapped, 10));
  });

  it('reuses the same MAC alias for a SEP<MAC>-style Device-ID and the frame source MAC', () => {
    const phoneMac = [0x00, 0x18, 0xba, 0xc8, 0xd1, 0x38];
    const deviceId = `SEP${phoneMac.map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join('')}`;
    const pkt = buildCdpFrame(deviceId, [10, 20, 30, 40]);
    // Overwrite the outer Ethernet source MAC to be the SAME phone MAC, unicast (LSB=0).
    pkt.set(phoneMac, 6);

    const mapping = new SessionMapping();
    const macMapped = mapping.map('mac', phoneMac.map((b) => b.toString(16).padStart(2, '0')).join(':'));
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    const exported = applyExport(pkt, result);
    const text = new TextDecoder('latin1').decode(exported);

    expect(text).not.toContain(deviceId);
    const expectedDeviceId = `SEP${macMapped.replace(/:/g, '').toUpperCase()}`;
    expect(text).toContain(expectedDeviceId);

    const srcMac = Array.from(exported.slice(6, 12)).map((b) => b.toString(16).padStart(2, '0')).join(':');
    expect(srcMac).toBe(macMapped);
  });
});
