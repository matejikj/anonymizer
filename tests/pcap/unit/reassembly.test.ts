import { describe, expect, it } from 'vitest';
import { TcpStreamReassembler } from '../../../src/pcap/reassembly/tcpStream';
import { IpFragmentReassembler } from '../../../src/pcap/reassembly/ipFragment';
import { runCaptureReassembly } from '../../../src/pcap/reassembly/capturePhase';
import { projectPatch } from '../../../src/pcap/reassembly/patchProject';
import { runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline';
import { buildSanitizationFromSnapshot } from '../../../src/pcap/plan/deterministicPlanBuilder';
import { resolveSnapshotForPackets } from './pcapSessionTestHelpers';
import type { PacketEnvelope } from '../../../src/pcap/domain/types';
import { DEFAULT_REASSEMBLY_LIMITS } from '../../../src/pcap/reassembly/limits';
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets';

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff));
}

function buildEthIpTcp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  seq: number,
  payload: Uint8Array,
): Uint8Array {
  const tcpLen = 20;
  const total = 14 + 20 + tcpLen + payload.length;
  const buf = new Uint8Array(total);
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
  buf[12] = 0x08;
  buf[13] = 0x00;
  buf[14] = 0x45;
  const ipTotalLen = 20 + tcpLen + payload.length;
  buf[16] = (ipTotalLen >> 8) & 0xff;
  buf[17] = ipTotalLen & 0xff;
  buf[23] = 6;
  buf.set(srcIp, 26);
  buf.set(dstIp, 30);
  const tcpStart = 34;
  buf[tcpStart] = (srcPort >> 8) & 0xff;
  buf[tcpStart + 1] = srcPort & 0xff;
  buf[tcpStart + 2] = (dstPort >> 8) & 0xff;
  buf[tcpStart + 3] = dstPort & 0xff;
  buf[tcpStart + 4] = (seq >> 24) & 0xff;
  buf[tcpStart + 5] = (seq >> 16) & 0xff;
  buf[tcpStart + 6] = (seq >> 8) & 0xff;
  buf[tcpStart + 7] = seq & 0xff;
  buf[tcpStart + 12] = 0x50;
  buf.set(payload, tcpStart + 20);
  return buf;
}

function buildSipInvite(): Uint8Array {
  const headers = [
    'INVITE sip:alice@192.168.1.10 SIP/2.0',
    'Via: SIP/2.0/TCP 192.168.1.10:5060;branch=z9hG4bK776',
    'From: <sip:alice@192.168.1.10>;tag=from-1',
    'Call-ID: dialog-tcp@192.168.1.10',
    'Content-Type: application/sdp',
    'Content-Length: 0',
  ];
  return latin1(`${headers.join('\r\n')}\r\n\r\n`);
}

function envelope(data: Uint8Array, index = 0): PacketEnvelope {
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

describe('TCP stream reassembly (step 9)', () => {
  it('reassembles SIP split across two segments in order', () => {
    const full = buildSipInvite();
    const mid = Math.floor(full.length / 2);
    const part1 = full.subarray(0, mid);
    const part2 = full.subarray(mid);

    const seg1 = {
      seq: 1000,
      packetIndex: 0,
      payloadOffset: 54,
      payloadLength: part1.length,
      captureOrder: 0,
    };
    const seg2 = {
      seq: 1000 + mid,
      packetIndex: 1,
      payloadOffset: 54,
      payloadLength: part2.length,
      captureOrder: 1,
    };

    const data = [
      buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, 1000, part1),
      buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, 1000 + mid, part2),
    ];

    const tcp = new TcpStreamReassembler({
      ...DEFAULT_REASSEMBLY_LIMITS,
      maxConcurrentFlows: 16,
      maxBytesPerFlow: 65536,
      maxFragmentGroups: 16,
    });

    for (const d of data) {
      tcp.ingest({
        packetIndex: data.indexOf(d),
        endpoint: { srcIp: '192.168.1.10', dstIp: '10.0.0.2', srcPort: 5060, dstPort: 5060, ipProto: 6 },
        seq: d === data[0] ? 1000 : 1000 + mid,
        payloadOffset: 54,
        payloadLength: d === data[0] ? part1.length : part2.length,
        syn: false,
        fin: false,
        rst: false,
        isFragment: false,
      });
    }

    const views = tcp.assembleAll(data);
    expect(views.length).toBe(1);
    expect(views[0]!.status).toBe('complete');
    expect(views[0]!.bytes.length).toBe(full.length);
    expect(Array.from(views[0]!.bytes)).toEqual(Array.from(full));
  });

  it('reassembles out-of-order TCP segments', () => {
    const full = buildSipInvite();
    const mid = Math.floor(full.length / 2);
    const part1 = full.subarray(0, mid);
    const part2 = full.subarray(mid);

    const pkt1 = buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, 1000 + mid, part2);
    const pkt0 = buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, 1000, part1);
    const data = [pkt0, pkt1];

    const tcp = new TcpStreamReassembler({
      ...DEFAULT_REASSEMBLY_LIMITS,
      maxConcurrentFlows: 16,
      maxBytesPerFlow: 65536,
      maxFragmentGroups: 16,
    });

    tcp.ingest({
      packetIndex: 1,
      endpoint: { srcIp: '192.168.1.10', dstIp: '10.0.0.2', srcPort: 5060, dstPort: 5060, ipProto: 6 },
      seq: 1000 + mid,
      payloadOffset: 54,
      payloadLength: part2.length,
      syn: false, fin: false, rst: false, isFragment: false,
    });
    tcp.ingest({
      packetIndex: 0,
      endpoint: { srcIp: '192.168.1.10', dstIp: '10.0.0.2', srcPort: 5060, dstPort: 5060, ipProto: 6 },
      seq: 1000,
      payloadOffset: 54,
      payloadLength: part1.length,
      syn: false, fin: false, rst: false, isFragment: false,
    });

    const views = tcp.assembleAll(data);
    expect(views[0]!.status).toBe('complete');
    expect(Array.from(views[0]!.bytes)).toEqual(Array.from(full));
  });

  it('PF-07: reassembles correctly without a SYN when sequence numbers wrap past 2^32', () => {
    // No SYN means pickBaseSeq() must find the true start itself — here the true start
    // (part1) sits right before the 32-bit wraparound, and part2/part3 land at small raw
    // seq values after wrapping. Naively picking the smallest raw seq as base (part2) would
    // be wrong; PF-07's O(n log n) largest-circular-gap search must still get this right.
    const full = buildSipInvite();
    const p1 = full.subarray(0, 5);
    const p2 = full.subarray(5, 10);
    const p3 = full.subarray(10);

    const SEQ1 = 0xfffffffb; // last 5 sequence numbers before wraparound
    const SEQ2 = (SEQ1 + p1.length) >>> 0; // wraps to 0
    const SEQ3 = (SEQ2 + p2.length) >>> 0;

    const pkt0 = buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, SEQ1, p1);
    const pkt1 = buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, SEQ2, p2);
    const pkt2 = buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, SEQ3, p3);
    // Ingested out of order too, to confirm sorting-by-raw-seq inside pickBaseSeq doesn't
    // depend on capture order.
    const data = [pkt1, pkt2, pkt0];

    const tcp = new TcpStreamReassembler({
      ...DEFAULT_REASSEMBLY_LIMITS,
      maxConcurrentFlows: 16,
      maxBytesPerFlow: 65536,
      maxFragmentGroups: 16,
    });

    const endpoint = { srcIp: '192.168.1.10', dstIp: '10.0.0.2', srcPort: 5060, dstPort: 5060, ipProto: 6 };
    tcp.ingest({ packetIndex: 0, endpoint, seq: SEQ2, payloadOffset: 54, payloadLength: p2.length, syn: false, fin: false, rst: false, isFragment: false });
    tcp.ingest({ packetIndex: 1, endpoint, seq: SEQ3, payloadOffset: 54, payloadLength: p3.length, syn: false, fin: false, rst: false, isFragment: false });
    tcp.ingest({ packetIndex: 2, endpoint, seq: SEQ1, payloadOffset: 54, payloadLength: p1.length, syn: false, fin: false, rst: false, isFragment: false });

    const views = tcp.assembleAll(data);
    expect(views.length).toBe(1);
    expect(views[0]!.status).toBe('complete');
    expect(views[0]!.bytes.length).toBe(full.length);
    expect(Array.from(views[0]!.bytes)).toEqual(Array.from(full));
  });

  it('PF-07: pickBaseSeq scales past a couple thousand segments in a no-SYN flow', () => {
    const endpoint = { srcIp: '192.168.1.10', dstIp: '10.0.0.2', srcPort: 5060, dstPort: 5060, ipProto: 6 };
    const segmentCount = 2000;
    const segLen = 8;
    const data: Uint8Array[] = [];
    const tcp = new TcpStreamReassembler({
      ...DEFAULT_REASSEMBLY_LIMITS,
      maxConcurrentFlows: 16,
      maxBytesPerFlow: 1024 * 1024,
      maxFragmentGroups: 16,
    });

    for (let i = 0; i < segmentCount; i++) {
      const payload = new Uint8Array(segLen).fill(i & 0xff);
      const seq = i * segLen;
      data.push(buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, seq, payload));
      tcp.ingest({ packetIndex: i, endpoint, seq, payloadOffset: 54, payloadLength: segLen, syn: false, fin: false, rst: false, isFragment: false });
    }

    const start = performance.now();
    const views = tcp.assembleAll(data);
    const elapsed = performance.now() - start;

    expect(views.length).toBe(1);
    expect(views[0]!.status).toBe('complete');
    expect(views[0]!.bytes.length).toBe(segmentCount * segLen);
    // O(n^2) pairwise pickBaseSeq at n=2000 is ~4,000,000 inner-loop iterations; O(n log n)
    // is a comfortable fraction of that. The bound is generous but would not hold for the
    // old algorithm run repeatedly across many flows in a large capture.
    expect(elapsed).toBeLessThan(200);
  });
});

describe('IPv4 fragment reassembly (step 9)', () => {
  it('detects overlapping fragment conflict', () => {
    const ipFrag = new IpFragmentReassembler({
      ...DEFAULT_REASSEMBLY_LIMITS,
      maxConcurrentFlows: 16,
      maxBytesPerFlow: 65536,
      maxFragmentGroups: 16,
    });

    const frag1 = buildIpv4Fragment([192, 168, 1, 1], [10, 0, 0, 2], 17, 0x1234, 0, true, latin1('ABCD'), 0);
    const frag2 = buildIpv4Fragment([192, 168, 1, 1], [10, 0, 0, 2], 17, 0x1234, 0, true, latin1('WXYZ'), 1);

    ipFrag.ingestIpv4(frag1);
    ipFrag.ingestIpv4(frag2);

    const views = ipFrag.assembleAll([frag1.data, frag2.data]);
    expect(views[0]!.status).toBe('overlap-conflict');
  });
});

function buildIpv4Fragment(
  srcIp: number[],
  dstIp: number[],
  proto: number,
  id: number,
  fragOffsetBytes: number,
  moreFragments: boolean,
  payload: Uint8Array,
  packetIndex: number,
) {
  const ihl = 20;
  const total = 14 + ihl + payload.length;
  const buf = new Uint8Array(total);
  buf[14] = 0x45;
  const ipLen = ihl + payload.length;
  buf[16] = (ipLen >> 8) & 0xff;
  buf[17] = ipLen & 0xff;
  buf[18] = (id >> 8) & 0xff;
  buf[19] = id & 0xff;
  const fragWords = (fragOffsetBytes / 8) & 0x1fff;
  buf[20] = ((moreFragments ? 0x20 : 0) | ((fragWords >> 8) & 0x1f)) & 0xff;
  buf[21] = fragWords & 0xff;
  buf[23] = proto;
  buf.set(srcIp, 26);
  buf.set(dstIp, 30);
  buf.set(payload, 14 + ihl);
  return {
    packetIndex,
    srcIp: srcIp.join('.'),
    dstIp: dstIp.join('.'),
    ipProto: proto,
    identification: id,
    fragmentOffset: fragOffsetBytes,
    moreFragments,
    payloadOffset: 14 + ihl,
    payloadLength: payload.length,
    data: buf,
  };
}

describe('Patch projection (step 9)', () => {
  it('projects reassembled offset back to source packet', () => {
    const provenance = [{
      assembledOffset: 10,
      packetIndex: 1,
      packetOffset: 100,
      length: 20,
    }];
    const patchData = latin1('REDACTED');
    const projected = projectPatch(provenance, 15, patchData.subarray(0, 5));
    expect(projected).toHaveLength(1);
    expect(projected[0]!.packetIndex).toBe(1);
    expect(projected[0]!.patch.offset).toBe(105);
  });
});

describe('Capture reassembly E2E (step 9)', () => {
  it('discovers SIP entities from TCP-segmented INVITE', () => {
    const full = buildSipInvite();
    const mid = Math.floor(full.length / 2);
    const packets = [
      envelope(buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, 1000, full.subarray(0, mid)), 0),
      envelope(buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, 1000 + mid, full.subarray(mid)), 1),
    ];

    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY);
    expect(reassembly.views.some((v) => v.status === 'complete')).toBe(true);

    const discovery = runDiscoveryPipeline(packets, DIAGNOSTIC_POLICY, 'gen', 'pcap', {
      reassemblyContext: reassembly,
    });

    const callIdIntents = discovery.intents.filter(
      (i) => i.kind === 'entity-replacement' && i.category === 'sip-call-id',
    );
    expect(callIdIntents.length).toBeGreaterThan(0);
  });

  it('marks incomplete TCP SIP as requires-reassembly when only first segment present', () => {
    const full = buildSipInvite();
    const mid = Math.floor(full.length / 2);
    const packets = [
      envelope(buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, 1000, full.subarray(0, mid)), 0),
    ];

    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY);
    const discovery = runDiscoveryPipeline(packets, DIAGNOSTIC_POLICY, 'gen', 'pcap', {
      reassemblyContext: reassembly,
    });

    expect(
      discovery.packetDiscovery[0]?.coverage.some((c) => c.status === 'requires-reassembly'),
    ).toBe(true);
  });

  it('applies projected patches during plan build', () => {
    const full = buildSipInvite();
    const mid = Math.floor(full.length / 2);
    const packets = [
      envelope(buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, 1000, full.subarray(0, mid)), 0),
      envelope(buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, 1000 + mid, full.subarray(mid)), 1),
    ];

    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY);
    const snapshot = resolveSnapshotForPackets(packets, DIAGNOSTIC_POLICY, 'reassembly', 'reassembly.pcap', reassembly);
    const results = buildSanitizationFromSnapshot(packets, DIAGNOSTIC_POLICY, snapshot, reassembly);
    const totalPatches = results.reduce((n, r) => n + r.patches.length, 0);
    expect(totalPatches).toBeGreaterThan(0);
  });
});
