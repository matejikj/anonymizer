import { describe, expect, it } from 'vitest';
import { MappingAuthority } from '../../../src/mapping/mappingAuthority';
import {
  buildCombinedSipSdpPlan,
  classifySipPayload,
  parseSipMessage,
} from '../../../src/pcap/protocols/application/sip';
import {
  buildDeterministicPlan,
  planWireSignature,
} from '../../../src/pcap/plan/deterministicPlanBuilder';
import {
  identitiesFromDiscovery,
  runDiscoveryPipeline,
} from '../../../src/pcap/discovery/discoveryPipeline';
import { CaptureFormat, Endian, TimestampResolution, type PacketEnvelope } from '../../../src/pcap/domain/types';
import { policyFromPreset } from '../../../src/pcap/sanitize/engine';
import { sanitizeSip, sanitizeSipMessage } from '../../../src/pcap/sanitize/sip';
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector';
import { SessionMapping, DEFAULT_MAPPING_CONFIG } from '../../../src/pcap/anonymization/mapping';
import { previewBytesFromPlan, buildExportEnvelope } from '../../../src/pcap/export/packetBuilder';
import { buildPlanSnapshot } from '../../../src/pcap/export/planSnapshot';
import { createDefaultPcapProfile } from '../../../src/pcap/profile/presets';
import { locateLayers } from '../../../src/pcap/checksums/locate';
import { TimestampMapping } from '../../../src/pcap/anonymization/timestampMapping';

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

function buildSipInviteWithSdp(sharedIp: string): Uint8Array {
  const sdp = [
    'v=0',
    `o=- 1 2 IN IP4 ${sharedIp}`,
    `c=IN IP4 ${sharedIp}`,
    'm=audio 54400 RTP/AVP 0',
    'a=candidate:1 1 UDP 2130706431 192.168.1.55 54401 typ host',
  ].join('\r\n');
  const headers = [
    `INVITE sip:bob@${sharedIp} SIP/2.0`,
    `Via: SIP/2.0/UDP ${sharedIp}:5060;branch=z9hG4bK776asdhds`,
    `From: <sip:bob@${sharedIp}>;tag=from-tag-1`,
    `Call-ID: dialog-1@${sharedIp}`,
    'User-Agent: SecretPhoneModel-X1 v2.3.4',
    'Content-Type: application/sdp',
    `Content-Length: ${sdp.length}`,
  ];
  return latin1(`${headers.join('\r\n')}\r\n\r\n${sdp}`);
}

function packetEnvelope(data: Uint8Array, index = 0): PacketEnvelope {
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

function checksumSkipOffsets(data: Uint8Array, linkType: number): Set<number> {
  const skip = new Set<number>();
  const layers = locateLayers(data, linkType, data.length);
  if (layers.l3Proto === 'ipv4') skip.add(layers.l3Offset + 10).add(layers.l3Offset + 11);
  if (layers.l4Proto === 'udp') skip.add(layers.l4Offset + 6).add(layers.l4Offset + 7);
  return skip;
}

describe('Structured SIP/SDP sanitization (step 7)', () => {
  it('re-parses exported UDP SIP payload after structured sanitization', () => {
    const sharedIp = '192.168.1.10';
    const payload = buildSipInviteWithSdp(sharedIp);
    const data = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, payload);
    const udpOffset = 42;
    const classified = classifySipPayload(data, udpOffset, payload.length, { portHint: true });
    expect(classified.kind).toBe('complete');
    if (classified.kind !== 'complete') return;

    const collector = new PatchCollector(data.length);
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' });
    sanitizeSipMessage(data, classified.message, 'udp', collector, mapping);

    const output = new Uint8Array(data);
    for (const patch of collector.getPatches()) output.set(patch.data, patch.offset);
    const outputStr = new TextDecoder('ascii', { fatal: false }).decode(output.slice(udpOffset));
    expect(outputStr).not.toContain('SecretPhoneModel-X1');
    expect(outputStr).not.toContain(sharedIp);
    expect(outputStr).not.toContain('192.168.1.55');
    expect(outputStr).not.toContain('54400');
    expect(outputStr).not.toContain('54401');

    const reparsed = classifySipPayload(output, udpOffset, payload.length, { portHint: true });
    expect(reparsed.kind).toBe('complete');
  });

  it('returns false for non-SIP and incomplete payloads (no regex fallback)', () => {
    const garbage = latin1('GET / HTTP/1.1\r\nHost: example\r\n\r\n');
    expect(sanitizeSip(garbage, 0, garbage.length, new PatchCollector(64), new SessionMapping())).toBe(false);

    const incomplete = latin1('INVITE sip:a@b SIP/2.0\r\nContent-Length: 999\r\n\r\n');
    expect(sanitizeSip(incomplete, 0, incomplete.length, new PatchCollector(64), new SessionMapping())).toBe(false);
  });

  it('preview matches export envelope for SIP-over-UDP plan (except checksums)', () => {
    const sharedIp = '192.168.1.10';
    const payload = buildSipInviteWithSdp(sharedIp);
    const data = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, payload);
    const packets = [packetEnvelope(data)];
    const policy = policyFromPreset('diagnostic');
    const profile = createDefaultPcapProfile().profile;

    const discovery = runDiscoveryPipeline(packets, policy, 'gen', 'pcap');
    const authority = new MappingAuthority({
      ip: profile.mapping.ip,
      mac: profile.mapping.mac,
      timestamps: profile.mapping.timestamps,
      ephemeralPorts: profile.mapping.ephemeralPorts,
      contentSignalingPorts: profile.mapping.contentSignalingPorts,
      vlan: profile.mapping.vlan,
    });
    const resolved = authority.resolve({
      generationId: 'gen',
      sourceId: 'pcap',
      identities: identitiesFromDiscovery(discovery),
    });
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;

    const plan1 = buildDeterministicPlan({
      generationId: 'gen',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'sip.pcap',
      packets,
      policy,
      snapshot: resolved.snapshot,
    });
    const plan2 = buildDeterministicPlan({
      generationId: 'gen',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'sip.pcap',
      packets,
      policy,
      snapshot: resolved.snapshot,
    });
    expect(planWireSignature(plan1)).toBe(planWireSignature(plan2));

    const sanPlan = buildPlanSnapshot({
      generationId: 'gen',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'sip.pcap',
      packets,
      sanitization: plan1.packets.map((p, i) => ({
        index: i,
        packetNumber: packets[i]!.packetNumber,
        patches: p.patches,
        coverage: [],
        issues: [],
        drop: p.drop,
        truncatedLength: p.truncatedLength,
      })),
      classicHeader: {
        format: CaptureFormat.ClassicPcap,
        endian: Endian.Little,
        timestampResolution: TimestampResolution.Microseconds,
        versionMajor: 2,
        versionMinor: 4,
        snapLen: 65535,
        linkType: 1,
        tzOffset: 0,
        sigfigs: 0,
      },
    });

    const preview = previewBytesFromPlan(packets[0]!, sanPlan.packets[0]!);
    const { envelope: exported } = buildExportEnvelope(
      packets[0]!,
      sanPlan.packets[0]!,
      new TimestampMapping(),
      true,
    );
    const skip = checksumSkipOffsets(exported.data, 1);
    for (let i = 0; i < preview.length; i++) {
      if (skip.has(i)) continue;
      expect(exported.data[i]).toBe(preview[i]);
    }
  });

  it('buildCombinedSipSdpPlan drops overlapping spans deterministically', () => {
    const payload = buildSipInviteWithSdp('10.0.0.1');
    const parsed = parseSipMessage(payload);
    expect(parsed.kind).toBe('complete');
    if (parsed.kind !== 'complete') return;
    const plan = buildCombinedSipSdpPlan(parsed.message, payload);
    expect(plan.operations.length).toBeGreaterThan(0);
    let lastEnd = -1;
    for (const op of plan.operations) {
      expect(op.span.offset).toBeGreaterThanOrEqual(lastEnd);
      lastEnd = op.span.offset + op.span.length;
    }
  });
});
