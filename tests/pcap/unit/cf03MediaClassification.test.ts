/**
 * CF-03 — capture-level media classification and real drop/truncate.
 */

import { describe, expect, it } from 'vitest';
import { MediaFlowIndex } from '../../../src/pcap/discovery/mediaFlowIndex';
import { runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline';
import { buildSanitizationFromSnapshot } from '../../../src/pcap/plan/deterministicPlanBuilder';
import { DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/profile/presets';
import { policyFromPreset, sanitizePacket } from '../../../src/pcap/sanitize/engine';
import type { PacketEnvelope } from '../../../src/pcap/domain/types';
import { SessionMapping } from '../../../src/pcap/anonymization/mapping';
import { resolveSnapshotForPackets } from './pcapSessionTestHelpers';

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff));
}

function buildEthIpUdp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const total = 14 + 20 + 8 + payload.length;
  const buf = new Uint8Array(total);
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
  buf[12] = 0x08;
  buf[13] = 0x00;
  buf[14] = 0x45;
  const ipTotalLen = 20 + 8 + payload.length;
  buf[16] = (ipTotalLen >> 8) & 0xff;
  buf[17] = ipTotalLen & 0xff;
  buf[23] = 17;
  buf.set(srcIp, 26);
  buf.set(dstIp, 30);
  const udpStart = 34;
  buf[udpStart] = (srcPort >> 8) & 0xff;
  buf[udpStart + 1] = srcPort & 0xff;
  buf[udpStart + 2] = (dstPort >> 8) & 0xff;
  buf[udpStart + 3] = dstPort & 0xff;
  const udpTotalLen = 8 + payload.length;
  buf[udpStart + 4] = (udpTotalLen >> 8) & 0xff;
  buf[udpStart + 5] = udpTotalLen & 0xff;
  buf.set(payload, udpStart + 8);
  return buf;
}

function buildRtpPayload(ssrc = 0x12345678, sequence = 1, timestamp = 160): Uint8Array {
  const buf = new Uint8Array(12 + 24);
  buf[0] = 0x80;
  buf[1] = 0;
  buf[2] = (sequence >> 8) & 0xff;
  buf[3] = sequence & 0xff;
  buf[4] = (timestamp >> 24) & 0xff;
  buf[5] = (timestamp >> 16) & 0xff;
  buf[6] = (timestamp >> 8) & 0xff;
  buf[7] = timestamp & 0xff;
  buf[8] = (ssrc >> 24) & 0xff;
  buf[9] = (ssrc >> 16) & 0xff;
  buf[10] = (ssrc >> 8) & 0xff;
  buf[11] = ssrc & 0xff;
  for (let i = 12; i < buf.length; i++) buf[i] = 0xa5;
  return buf;
}

function buildRtcpSdes(cname = 'alice@192.168.1.10'): Uint8Array {
  const cnameBytes = latin1(cname);
  const chunkLen = 4 + 2 + cnameBytes.length + 1;
  const padded = chunkLen + (4 - (chunkLen % 4)) % 4;
  const buf = new Uint8Array(4 + padded);
  buf[0] = 0x81;
  buf[1] = 202;
  const words = padded / 4;
  buf[2] = (words >> 8) & 0xff;
  buf[3] = words & 0xff;
  buf[4] = 0x12;
  buf[5] = 0x34;
  buf[6] = 0x56;
  buf[7] = 0x78;
  buf[8] = 1;
  buf[9] = cnameBytes.length;
  buf.set(cnameBytes, 10);
  return buf;
}

function buildSipInviteWithSdp(sharedIp: string, mediaPort = 54400): Uint8Array {
  const sdp = [
    'v=0',
    `o=- 1 2 IN IP4 ${sharedIp}`,
    `c=IN IP4 ${sharedIp}`,
    `m=audio ${mediaPort} RTP/AVP 0`,
  ].join('\r\n');
  const headers = [
    `INVITE sip:alice@${sharedIp} SIP/2.0`,
    `Via: SIP/2.0/UDP ${sharedIp}:5060;branch=z9hG4bK776asdhds`,
    `From: <sip:alice@${sharedIp}>;tag=from-tag-1`,
    `Call-ID: dialog-1@${sharedIp}`,
    'Content-Type: application/sdp',
    `Content-Length: ${sdp.length}`,
  ];
  return latin1(`${headers.join('\r\n')}\r\n\r\n${sdp}`);
}

function envelopeFromPacket(data: Uint8Array, index = 0): PacketEnvelope {
  return {
    packetNumber: index,
    timestamp: { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 24,
    data,
  };
}

function exportBytes(
  original: Uint8Array,
  drop: boolean,
  truncatedLength?: number,
  patches: readonly { offset: number; data: Uint8Array }[] = [],
): Uint8Array {
  if (drop) return new Uint8Array(0);
  const len = truncatedLength ?? original.length;
  const out = original.slice(0, len);
  for (const patch of patches) {
    if (patch.offset + patch.data.length > out.length) continue;
    out.set(patch.data, patch.offset);
  }
  return out;
}

function containsCanary(bytes: Uint8Array, canary: number): boolean {
  for (const b of bytes) if (b === canary) return true;
  return false;
}

describe('CF-03 media classification', () => {
  const sharedIp = '192.168.1.10';
  const mediaPort = 54400;

  it('RTP without SDP is suspected and stripped in-place under diagnostic (not truncated)', () => {
    const rtp = buildEthIpUdp(
      [192, 168, 1, 10],
      [10, 0, 0, 2],
      mediaPort,
      40000,
      buildRtpPayload(),
    );
    const input = {
      index: 0,
      data: rtp,
      capturedLength: rtp.length,
      originalLength: rtp.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping(), {
      mediaFlowIndex: new MediaFlowIndex(),
    });

    expect(result.drop).toBe(false);
    expect(result.coverage.some((c) => c.protocol === 'rtp' && c.status === 'redacted')).toBe(true);
    expect(result.truncatedLength).toBeUndefined();
    expect(result.patches.length).toBeGreaterThan(0);
    const exported = exportBytes(rtp, result.drop, result.truncatedLength, result.patches);
    // Canary lives in RTP media bytes after the fixed 12-byte header (UDP payload @ 42).
    const mediaStart = 42 + 12;
    expect(containsCanary(exported.subarray(mediaStart), 0xa5)).toBe(false);
  });

  it('high-privacy truncates suspected RTP without SDP', () => {
    const rtp = buildEthIpUdp(
      [192, 168, 1, 10],
      [10, 0, 0, 2],
      mediaPort,
      40000,
      buildRtpPayload(),
    );
    const input = {
      index: 0,
      data: rtp,
      capturedLength: rtp.length,
      originalLength: rtp.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, new SessionMapping(), {
      mediaFlowIndex: new MediaFlowIndex(),
    });

    expect(result.drop).toBe(false);
    expect(result.coverage.some((c) => c.protocol === 'rtp' && c.status === 'unsupported')).toBe(true);
    expect(result.truncatedLength).toBeDefined();
    expect(result.truncatedLength!).toBeLessThan(rtp.length);
    expect(containsCanary(exportBytes(rtp, result.drop, result.truncatedLength), 0xa5)).toBe(false);
  });

  it('a single random RTP-shaped packet without flow evidence is only ever "suspected", never "confirmed"', () => {
    const index = new MediaFlowIndex();
    const payload = buildRtpPayload(0xabcdef01, 42);
    const classification = index.classify({
      srcIp: sharedIp,
      dstIp: '10.0.0.2',
      srcPort: 5004,
      dstPort: 5004,
      payload,
      payloadOffset: 0,
      payloadLength: payload.length,
    });
    expect(classification?.kind).toBe('rtp');
    expect(classification?.confidence).toBe('suspected');
  });

  it('confirms RTP after stable SSRC + advancing sequence (no SDP)', () => {
    const index = new MediaFlowIndex();
    const ssrc = 0x11112222;
    const classify = (seq: number) => index.classify({
      srcIp: sharedIp,
      dstIp: '10.0.0.2',
      srcPort: 5004,
      dstPort: 5006,
      payload: buildRtpPayload(ssrc, seq, seq * 160),
      payloadOffset: 0,
      payloadLength: 36,
    });

    expect(classify(1)?.confidence).toBe('suspected');
    expect(classify(2)?.confidence).toBe('confirmed');
    expect(classify(3)?.confidence).toBe('confirmed');
  });

  it('keeps confirmed RTP/RTCP under diagnostic strip-payload and masks media bytes', () => {
    const packets = [
      envelopeFromPacket(
        buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5004, 5006, buildRtpPayload(0x55, 1)),
        0,
      ),
      envelopeFromPacket(
        buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5004, 5006, buildRtpPayload(0x55, 2)),
        1,
      ),
      envelopeFromPacket(
        buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5005, 5007, buildRtcpSdes()),
        2,
      ),
      envelopeFromPacket(
        buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5005, 5007, buildRtcpSdes()),
        3,
      ),
    ];

    const discovery = runDiscoveryPipeline(packets, DIAGNOSTIC_POLICY, 'gen', 'pcap');
    expect(discovery.packetDiscovery.every((p) => !p.drop)).toBe(true);
    expect(discovery.packetDiscovery[0]?.truncatedLength).toBeUndefined();
    expect(discovery.packetDiscovery[1]?.coverage.some((c) => c.protocol === 'rtp' && c.status === 'redacted')).toBe(true);
    // RTCP strip-payload masks identities but keeps SR/RR framing → covered (T63 refine).
    expect(discovery.packetDiscovery[3]?.coverage.some((c) => c.protocol === 'rtcp' && c.status === 'covered')).toBe(true);

    const snapshot = resolveSnapshotForPackets(packets, DIAGNOSTIC_POLICY, 'cf03', 'cf03.pcap');
    const sanitization = buildSanitizationFromSnapshot(packets, DIAGNOSTIC_POLICY, snapshot);
    for (const san of sanitization) {
      expect(san.drop).toBe(false);
      const pkt = packets[san.packetIndex]!;
      const exported = exportBytes(pkt.data, san.drop, san.truncatedLength, san.patches);
      // Canary is the RTP media fill byte; headers may coincidentally contain 0xa5 after remap.
      const mediaStart = 42 + 12;
      expect(containsCanary(exported.subarray(mediaStart), 0xa5)).toBe(false);
      const text = new TextDecoder('ascii', { fatal: false }).decode(exported);
      expect(text).not.toContain('alice@192.168.1.10');
    }
  });

  it('explicit mediaPolicy=drop still drops confirmed RTP/RTCP', () => {
    const packets = [
      envelopeFromPacket(
        buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5004, 5006, buildRtpPayload(0x55, 1)),
        0,
      ),
      envelopeFromPacket(
        buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5004, 5006, buildRtpPayload(0x55, 2)),
        1,
      ),
      envelopeFromPacket(
        buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5005, 5007, buildRtcpSdes()),
        2,
      ),
      envelopeFromPacket(
        buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5005, 5007, buildRtcpSdes()),
        3,
      ),
    ];
    const policy = { ...DIAGNOSTIC_POLICY, mediaPolicy: 'drop' as const };

    const discovery = runDiscoveryPipeline(packets, policy, 'gen', 'pcap');
    expect(discovery.packetDiscovery[0]?.drop).toBe(false);
    expect(discovery.packetDiscovery[1]?.drop).toBe(true);
    expect(discovery.packetDiscovery[3]?.drop).toBe(true);
  });

  it('keeps RTP/RTCP when SDP arrives after media under strip-payload', () => {
    const rtpEarly = envelopeFromPacket(
      buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort, 40000, buildRtpPayload()),
      0,
    );
    const sip = envelopeFromPacket(
      buildEthIpUdp(
        [192, 168, 1, 10],
        [10, 0, 0, 2],
        5060,
        5060,
        buildSipInviteWithSdp(sharedIp, mediaPort),
      ),
      1,
    );
    const rtpLate = envelopeFromPacket(
      buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort, 40000, buildRtpPayload(0x99, 5)),
      2,
    );
    const rtcp = envelopeFromPacket(
      buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort + 1, 40001, buildRtcpSdes()),
      3,
    );
    const packets = [rtpEarly, sip, rtpLate, rtcp];

    const discovery = runDiscoveryPipeline(packets, DIAGNOSTIC_POLICY, 'gen', 'pcap');
    expect(discovery.packetDiscovery.every((p) => !p.drop)).toBe(true);
    expect(discovery.packetDiscovery[0]?.truncatedLength).toBeUndefined();
    expect(discovery.packetDiscovery[2]?.coverage.some((c) => c.protocol === 'rtp')).toBe(true);
    expect(discovery.packetDiscovery[3]?.coverage.some((c) => c.protocol === 'rtcp')).toBe(true);

    const snapshot = resolveSnapshotForPackets(packets, DIAGNOSTIC_POLICY, 'cf03-order', 'cf03.pcap');
    const sanitization = buildSanitizationFromSnapshot(packets, DIAGNOSTIC_POLICY, snapshot);
    for (const san of sanitization) {
      if (san.packetIndex === 1) continue; // SIP
      const pkt = packets[san.packetIndex]!;
      const exported = exportBytes(pkt.data, san.drop, san.truncatedLength, san.patches);
      const mediaStart = 42 + 12;
      expect(containsCanary(exported.subarray(mediaStart), 0xa5)).toBe(false);
    }
  });

  it('preserve-unsafe mediaPolicy is remapped on fixed levels (T68)', () => {
    const packets = [
      envelopeFromPacket(
        buildEthIpUdp(
          [192, 168, 1, 10],
          [10, 0, 0, 2],
          5060,
          5060,
          buildSipInviteWithSdp(sharedIp, mediaPort),
        ),
        0,
      ),
      envelopeFromPacket(
        buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort, 40000, buildRtpPayload()),
        1,
      ),
    ];
    const policy = {
      ...policyFromPreset('diagnostic'),
      mediaPolicy: 'preserve-unsafe' as const,
    };
    const discovery = runDiscoveryPipeline(packets, policy, 'gen', 'pcap');
    expect(discovery.packetDiscovery[1]?.drop).toBe(false);
    // T68 remaps preserve-unsafe → strip/mask; never leave preserved-unsafe on the wire path.
    expect(
      discovery.packetDiscovery[1]?.coverage.some(
        (c) => c.protocol === 'rtp' && c.status === 'preserved-unsafe',
      ),
    ).toBe(false);
  });

  it('never sends RTP-shaped UDP to heuristic scanner', () => {
    const rtp = buildEthIpUdp(
      [192, 168, 1, 10],
      [10, 0, 0, 2],
      5004,
      5006,
      buildRtpPayload(),
    );
    const result = sanitizePacket(
      {
        index: 0,
        data: rtp,
        capturedLength: rtp.length,
        originalLength: rtp.length,
        linkType: 1,
      },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
    );
    expect(result.coverage.some((c) => c.protocol === 'heuristic')).toBe(false);
    expect(result.coverage.some((c) => c.protocol === 'rtp')).toBe(true);
  });

  it('excludes SIP signaling ports from shape-only RTP/RTCP classification', () => {
    const index = new MediaFlowIndex();
    // Bytes that would otherwise look like a valid RTP header, but on the SIP port.
    const payload = buildRtpPayload(0xdeadbeef, 7);
    const classification = index.classify({
      srcIp: sharedIp,
      dstIp: '10.0.0.2',
      srcPort: 5060,
      dstPort: 5060,
      payload,
      payloadOffset: 0,
      payloadLength: payload.length,
    });
    expect(classification).toBeNull();
  });
});
