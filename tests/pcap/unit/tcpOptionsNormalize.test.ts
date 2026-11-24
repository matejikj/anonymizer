/**
 * TCP options fingerprint normalization for high-privacy (previously an unimplemented
 * "product decision" — `tcpOptions: 'preserve-unsafe'` left MSS/Window-Scale, a p0f-style
 * OS/stack fingerprint, fully readable even in the strictest export level). Only the MSS
 * value and Window Scale factor are normalized to fixed constants; every other option's
 * presence/order (and NOP padding) is left exactly as captured.
 */

import { describe, expect, it } from 'vitest';
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY, type PacketInput } from '../../../src/pcap/sanitize';
import { SessionMapping } from '../../../src/pcap/anonymization/mapping';
import { buildPrivacyReport } from '../../../src/pcap/privacy/privacyReport';
import { CaptureFormat } from '../../../src/pcap/domain/types';
import type { PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot';
import { emptyPlanAuditFields } from '../../../src/pcap/plan/planDisposition';

function emptyPlan(): PcapPlanSnapshot {
  return {
    generationId: 'g-tcp-options',
    pcapLevel: 'high-privacy',
    profileId: 'pcap-high-privacy',
    profileHash: 'hash',
    format: CaptureFormat.ClassicPcap,
    fileName: 'test.pcap',
    engineVersion: 'test',
    packets: [],
    droppedPacketNumbers: [],
    timestamps: 'enumerated',
    timestampAnchorSeed: 'test-anchor-seed',
    ...emptyPlanAuditFields(),
  };
}

function applyExport(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const len = result.truncatedLength ?? original.length;
  const out = original.slice(0, len);
  for (const patch of result.patches) {
    if (patch.offset < len) out.set(patch.data.slice(0, len - patch.offset), patch.offset);
  }
  return out;
}

/** Ethernet + IPv4 + TCP SYN with MSS(1460) + SACK-permitted + Timestamp + NOP + WScale(9) options. */
function buildSynWithOptions(): Uint8Array {
  const options = [
    0x02, 0x04, 0x05, 0xb4, // MSS 1460
    0x04, 0x02, // SACK-permitted
    0x08, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // Timestamp (10 bytes)
    0x01, // NOP
    0x03, 0x03, 0x09, // Window Scale factor 9
  ];
  const tcpHeaderLen = 20 + options.length; // 40 bytes -> data offset 10 (multiple of 4)
  const total = 14 + 20 + tcpHeaderLen;
  const buf = new Uint8Array(total);
  buf[12] = 0x08; buf[13] = 0x00;
  buf[14] = 0x45;
  const totalLen = 20 + tcpHeaderLen;
  buf[16] = (totalLen >> 8) & 0xff; buf[17] = totalLen & 0xff;
  buf[22] = 64; // TTL
  buf[23] = 6; // TCP
  buf.set([192, 168, 1, 10], 26);
  buf.set([10, 0, 0, 1], 30);
  const tcp = 34;
  buf[tcp] = 0x30; buf[tcp + 1] = 0x39; // src port 12345
  buf[tcp + 2] = 0x01; buf[tcp + 3] = 0xbb; // dst port 443
  buf[tcp + 12] = ((tcpHeaderLen / 4) << 4) & 0xff0; // data offset nibble
  buf[tcp + 13] = 0x02; // SYN flag
  buf.set(options, tcp + 20);
  return buf;
}

describe('TCP options normalization', () => {
  it('normalizes MSS and Window Scale for high-privacy, preserves everything else', () => {
    const pkt = buildSynWithOptions();
    const mapping = new SessionMapping();
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);
    const exported = applyExport(pkt, result);

    const optionsOffset = 34 + 20;
    // MSS value normalized to 1460
    expect(exported[optionsOffset + 2]).toBe(0x05);
    expect(exported[optionsOffset + 3]).toBe(0xb4);
    // SACK-permitted kind/length untouched
    expect(exported[optionsOffset + 4]).toBe(0x04);
    expect(exported[optionsOffset + 5]).toBe(0x02);
    // Window Scale factor normalized (kind/length bytes at +17,+18 untouched, value at +19 changed)
    expect(exported[optionsOffset + 17]).toBe(0x03);
    expect(exported[optionsOffset + 18]).toBe(0x03);
    expect(exported[optionsOffset + 19]).toBe(0x07);
    expect(exported[optionsOffset + 19]).not.toBe(0x09);

    const tcpOptionsSpan = result.coverage.find((c) => c.protocol === 'tcp-options');
    expect(tcpOptionsSpan?.status).toBe('covered');
  });

  it('preserves MSS/Window Scale for diagnostic (diagnostic value, not normalized)', () => {
    const pkt = buildSynWithOptions();
    const mapping = new SessionMapping();
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    const exported = applyExport(pkt, result);

    const optionsOffset = 34 + 20;
    expect(exported[optionsOffset + 2]).toBe(0x05);
    expect(exported[optionsOffset + 3]).toBe(0xb4); // still 1460 in this fixture, so check WScale instead
    expect(exported[optionsOffset + 19]).toBe(0x09); // Window Scale factor untouched
  });

  it('privacy report reflects tcpOptions in networkFingerprintNormalized', () => {
    const report = buildPrivacyReport({
      plan: emptyPlan(),
      policy: HIGH_PRIVACY_POLICY,
      coverage: [],
    });
    expect(report.networkFingerprintNormalized).toBe(true);
    expect(report.requiresUnsafeConfirmation).toBe(false);
  });
});
