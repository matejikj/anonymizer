import { describe, expect, it } from 'vitest';
import {
  looksLikeRtpPayload,
  looksLikeRtcpPayload,
} from '../../../src/pcap/protocols/application/rtp/classify';
import { MediaFlowIndex } from '../../../src/pcap/discovery/mediaFlowIndex';
import { discoverPacket } from '../../../src/pcap/discovery/discoverPacket';
import {
  buildSanitizationFromSnapshot,
} from '../../../src/pcap/plan/deterministicPlanBuilder';
import { runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline';
import type { PacketEnvelope } from '../../../src/pcap/domain/types';
import { policyFromPreset } from '../../../src/pcap/sanitize/engine';
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets';
import { classifySipPayload } from '../../../src/pcap/protocols/application/sip/classify';
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

function buildSipInviteWithSdp(sharedIp: string, mediaPort = 54400): Uint8Array {
  const sdp = [
    'v=0',
    `o=- 1 2 IN IP4 ${sharedIp}`,
    `c=IN IP4 ${sharedIp}`,
    `m=audio ${mediaPort} RTP/AVP 0`,
    // Explicit RTCP port (enterprise step 6 — do not invent p+1 without SDP signal).
    `a=rtcp:${mediaPort + 1}`,
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

function buildRtpPayload(payloadType = 0, ssrc = 0x12345678, sequence = 0x0100, timestamp = 1): Uint8Array {
  const buf = new Uint8Array(12 + 20);
  buf[0] = 0x80;
  buf[1] = payloadType & 0x7f;
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
  // Distinct voice-like canary bytes for leak checks
  for (let i = 12; i < buf.length; i++) buf[i] = 0xa5;
  return buf;
}

function buildRtcpSdes(ssrc = 0x12345678, cname = 'alice@192.168.1.10'): Uint8Array {
  const cnameBytes = latin1(cname);
  const chunkLen = 4 + 2 + cnameBytes.length + 1;
  const padded = chunkLen + (4 - (chunkLen % 4)) % 4;
  const buf = new Uint8Array(4 + padded);
  buf[0] = 0x81;
  buf[1] = 202;
  const words = (padded / 4);
  buf[2] = (words >> 8) & 0xff;
  buf[3] = words & 0xff;
  buf[4] = (ssrc >> 24) & 0xff;
  buf[5] = (ssrc >> 16) & 0xff;
  buf[6] = (ssrc >> 8) & 0xff;
  buf[7] = ssrc & 0xff;
  buf[8] = 1;
  buf[9] = cnameBytes.length;
  buf.set(cnameBytes, 10);
  return buf;
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

describe('RTP/RTCP packet-shape validation (step 8)', () => {
  it('accepts RTP v2 with matching payload type', () => {
    const payload = buildRtpPayload(0);
    expect(looksLikeRtpPayload(payload, 0, payload.length, ['0'])).toBe(true);
    expect(looksLikeRtpPayload(payload, 0, payload.length, ['8'])).toBe(false);
  });

  it('accepts RTCP SDES packet type', () => {
    const payload = buildRtcpSdes();
    expect(looksLikeRtcpPayload(payload, 0, payload.length)).toBe(true);
  });

  it('rejects random UDP payload as RTP', () => {
    const payload = latin1('not-rtp-data-at-all');
    expect(looksLikeRtpPayload(payload, 0, payload.length, ['0'])).toBe(false);
  });
});

describe('MediaFlowIndex (step 8)', () => {
  it('registers SDP endpoints and classifies RTP/RTCP by flow key + shape', () => {
    const sharedIp = '192.168.1.10';
    const sipPayload = buildSipInviteWithSdp(sharedIp, 54400);
    const sipPacket = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, sipPayload);
    const udpOffset = 34 + 8;
    const classified = classifySipPayload(sipPayload, 0, sipPayload.length, { portHint: true });
    expect(classified.kind).toBe('complete');
    if (classified.kind !== 'complete') return;

    const index = new MediaFlowIndex();
    index.registerFromSipMessage(classified.message, sipPayload);
    expect(index.size).toBeGreaterThan(0);

    const rtpPayload = buildRtpPayload(0);
    const rtpClass = index.classify({
      srcIp: sharedIp,
      dstIp: '10.0.0.2',
      srcPort: 54400,
      dstPort: 40000,
      payload: rtpPayload,
      payloadOffset: 0,
      payloadLength: rtpPayload.length,
    });
    expect(rtpClass?.kind).toBe('rtp');

    const rtcpPayload = buildRtcpSdes();
    const rtcpClass = index.classify({
      srcIp: sharedIp,
      dstIp: '10.0.0.2',
      srcPort: 54401,
      dstPort: 40001,
      payload: rtcpPayload,
      payloadOffset: 0,
      payloadLength: rtcpPayload.length,
    });
    expect(rtcpClass?.kind).toBe('rtcp');
  });

  it('does not classify by port alone without RTP/RTCP shape', () => {
    const sharedIp = '192.168.1.10';
    const sipPayload = buildSipInviteWithSdp(sharedIp, 54400);
    const classified = classifySipPayload(sipPayload, 0, sipPayload.length, { portHint: true });
    expect(classified.kind).toBe('complete');
    if (classified.kind !== 'complete') return;

    const index = new MediaFlowIndex();
    index.registerFromSipMessage(classified.message, sipPayload);

    const garbage = latin1('garbage-on-media-port');
    const result = index.classify({
      srcIp: sharedIp,
      dstIp: '10.0.0.2',
      srcPort: 54400,
      dstPort: 40000,
      payload: garbage,
      payloadOffset: 0,
      payloadLength: garbage.length,
    });
    expect(result).toBeNull();
  });
});

describe('VoIP media policy E2E (step 8)', () => {
  const sharedIp = '192.168.1.10';
  const mediaPort = 54400;

  function callFixtures(): PacketEnvelope[] {
    const sip = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, buildSipInviteWithSdp(sharedIp, mediaPort));
    const rtp = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort, 40000, buildRtpPayload(0));
    const rtcp = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort + 1, 40001, buildRtcpSdes());
    return [envelopeFromPacket(sip, 0), envelopeFromPacket(rtp, 1), envelopeFromPacket(rtcp, 2)];
  }

  it('diagnostic preset (sipSdp + mediaPolicy strip-payload) keeps RTP/RTCP records', () => {
    const packets = callFixtures();
    const policy = DIAGNOSTIC_POLICY;
    expect(policy.mediaPolicy).toBe('strip-payload');
    expect(policy.sipSdp).toBe(true);

    const discovery = runDiscoveryPipeline(packets, policy, 'gen', 'pcap');
    const dropIntents = discovery.intents.filter((i) => i.kind === 'drop-record');
    expect(dropIntents.map((i) => i.packetIndex)).toEqual([]);

    expect(discovery.packetDiscovery[1]?.drop).toBe(false);
    expect(discovery.packetDiscovery[2]?.drop).toBe(false);
    expect(discovery.packetDiscovery[0]?.drop).toBe(false);
    expect(discovery.packetDiscovery[1]?.coverage.some((c) => c.protocol === 'rtp')).toBe(true);
    expect(discovery.packetDiscovery[2]?.coverage.some((c) => c.protocol === 'rtcp')).toBe(true);

    const snapshot = resolveSnapshotForPackets(packets, policy, 'rtp-media', 'rtp-media.pcap');
    const sanitization = buildSanitizationFromSnapshot(packets, policy, snapshot);
    expect(sanitization[1]?.drop).toBe(false);
    expect(sanitization[2]?.drop).toBe(false);
    expect(sanitization.filter((s) => s.drop).length).toBe(0);
  });

  it('high-privacy still drops RTP/RTCP with drop-record intents', () => {
    const packets = callFixtures();
    const policy = { ...DIAGNOSTIC_POLICY, mediaPolicy: 'drop' as const, preset: 'high-privacy' as const };

    const discovery = runDiscoveryPipeline(packets, policy, 'gen', 'pcap');
    const dropIntents = discovery.intents.filter((i) => i.kind === 'drop-record');
    expect(dropIntents.map((i) => i.packetIndex).sort()).toEqual([1, 2]);
  });

  it('preserve-unsafe marks media as preserved-unsafe without dropping', () => {
    const packets = callFixtures();
    const policy = {
      ...policyFromPreset('diagnostic'),
      mediaPolicy: 'preserve-unsafe' as const,
    };

    const mediaFlowIndex = new MediaFlowIndex();
    const rtpDisc = discoverPacket(
      {
        index: 0,
        data: packets[0]!.data,
        capturedLength: packets[0]!.capturedLength,
        originalLength: packets[0]!.originalLength,
        linkType: packets[0]!.linkType,
      },
      0,
      policy,
      mediaFlowIndex,
    );
    expect(rtpDisc.drop).toBe(false);

    const rtpResult = discoverPacket(
      {
        index: 1,
        data: packets[1]!.data,
        capturedLength: packets[1]!.capturedLength,
        originalLength: packets[1]!.originalLength,
        linkType: packets[1]!.linkType,
      },
      1,
      policy,
      mediaFlowIndex,
    );
    expect(rtpResult.drop).toBe(false);
    expect(rtpResult.coverage.some((c) => c.protocol === 'rtp' && c.status === 'preserved-unsafe')).toBe(true);
  });

  it('classifies SRTP SDP as encrypted media and schedules strip under diagnostic strip-payload', () => {
    const sdp = [
      'v=0',
      `o=- 1 2 IN IP4 ${sharedIp}`,
      `c=IN IP4 ${sharedIp}`,
      `m=audio ${mediaPort} RTP/SAVP 0`,
      'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:base64key',
    ].join('\r\n');
    const headers = [
      `INVITE sip:alice@${sharedIp} SIP/2.0`,
      'Content-Type: application/sdp',
      `Content-Length: ${sdp.length}`,
    ];
    const sipPayload = latin1(`${headers.join('\r\n')}\r\n\r\n${sdp}`);
    const sipPacket = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, sipPayload);
    const rtpPayload = buildRtpPayload(0);

    const mediaFlowIndex = new MediaFlowIndex();
    discoverPacket(
      {
        index: 0,
        data: sipPacket,
        capturedLength: sipPacket.length,
        originalLength: sipPacket.length,
        linkType: 1,
      },
      0,
      policyFromPreset('diagnostic'),
      mediaFlowIndex,
    );

    const rtpPacket = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort, 40000, rtpPayload);
    const rtpResult = discoverPacket(
      {
        index: 1,
        data: rtpPacket,
        capturedLength: rtpPacket.length,
        originalLength: rtpPacket.length,
        linkType: 1,
      },
      1,
      policyFromPreset('diagnostic'),
      mediaFlowIndex,
    );
    expect(rtpResult.drop).toBe(false);
    expect(rtpResult.coverage.some((c) => c.protocol === 'srtp' && c.status === 'redacted')).toBe(true);
  });

  it('drops SRTP under explicit mediaPolicy=drop', () => {
    const sdp = [
      'v=0',
      `o=- 1 2 IN IP4 ${sharedIp}`,
      `c=IN IP4 ${sharedIp}`,
      `m=audio ${mediaPort} RTP/SAVP 0`,
      'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:base64key',
    ].join('\r\n');
    const headers = [
      `INVITE sip:alice@${sharedIp} SIP/2.0`,
      'Content-Type: application/sdp',
      `Content-Length: ${sdp.length}`,
    ];
    const sipPayload = latin1(`${headers.join('\r\n')}\r\n\r\n${sdp}`);
    const sipPacket = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, sipPayload);
    const rtpPayload = buildRtpPayload(0);
    const policy = { ...policyFromPreset('diagnostic'), mediaPolicy: 'drop' as const };

    const mediaFlowIndex = new MediaFlowIndex();
    discoverPacket(
      {
        index: 0,
        data: sipPacket,
        capturedLength: sipPacket.length,
        originalLength: sipPacket.length,
        linkType: 1,
      },
      0,
      policy,
      mediaFlowIndex,
    );

    const rtpPacket = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort, 40000, rtpPayload);
    const rtpResult = discoverPacket(
      {
        index: 1,
        data: rtpPacket,
        capturedLength: rtpPacket.length,
        originalLength: rtpPacket.length,
        linkType: 1,
      },
      1,
      policy,
      mediaFlowIndex,
    );
    expect(rtpResult.drop).toBe(true);
    expect(rtpResult.coverage.some((c) => c.protocol === 'srtp')).toBe(true);
  });

  it('PF-11: classify() stays O(1) per call regardless of registered flow count', () => {
    const index = new MediaFlowIndex();
    // registerFlowKey is private — exercising it directly is the simplest way to populate
    // thousands of flows without parsing that many synthetic SDP sessions; the point of this
    // test is purely to stress classify()'s lookup path, not SDP registration itself.
    const registerFlowKey = (index as unknown as {
      registerFlowKey: (key: { protocol: 'rtp' | 'rtcp'; ip: string; port: number }, encrypted: boolean, payloadTypes: readonly string[], callId: string | null) => void
    }).registerFlowKey.bind(index);

    const flowCount = 4000; // close to MAX_FLOW_ENTRIES
    for (let i = 0; i < flowCount; i++) {
      registerFlowKey({ protocol: 'rtp', ip: `10.${(i >> 16) & 0xff}.${(i >> 8) & 0xff}.${i & 0xff}`, port: 10000 + (i % 1000) }, false, ['0'], null);
    }

    // A packet matching none of the registered flows — worst case for a linear scan (has to
    // walk every entry before concluding "no match"), trivial for a keyed lookup.
    const rtpPayload = buildRtpPayload(0);
    const start = performance.now();
    for (let i = 0; i < 5000; i++) {
      index.classify({
        srcIp: '203.0.113.1',
        dstIp: '203.0.113.2',
        srcPort: 55000,
        dstPort: 55001,
        payload: rtpPayload,
        payloadOffset: 0,
        payloadLength: rtpPayload.length,
      });
    }
    const elapsed = performance.now() - start;

    // 5000 calls x 4000 flows = 20M comparisons for the old linear scan; O(1) lookups make
    // this trivial. Generous bound, unreachable under the old behavior.
    expect(elapsed).toBeLessThan(200);
  });
});
