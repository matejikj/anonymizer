/**
 * CF-04 / CF-05 — directional TCP reassembly and off-port / fragmented SIP.
 */

import { describe, expect, it } from 'vitest';
import { TcpStreamReassembler } from '../../../src/pcap/reassembly/tcpStream';
import { IpFragmentReassembler } from '../../../src/pcap/reassembly/ipFragment';
import { runCaptureReassembly } from '../../../src/pcap/reassembly/capturePhase';
import { unwrapTransportDatagram } from '../../../src/pcap/reassembly/transportUnwrap';
import { runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline';
import type { PacketEnvelope } from '../../../src/pcap/domain/types';
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets';
import { DEFAULT_REASSEMBLY_LIMITS } from '../../../src/pcap/reassembly/limits';

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
  buf[12] = 0x08;
  buf[13] = 0x00;
  buf[14] = 0x45;
  const ipTotalLen = 20 + 8 + payload.length;
  buf[16] = (ipTotalLen >> 8) & 0xff;
  buf[17] = ipTotalLen & 0xff;
  buf[23] = 17;
  buf.set(srcIp, 26);
  buf.set(dstIp, 30);
  buf[34] = (srcPort >> 8) & 0xff;
  buf[35] = srcPort & 0xff;
  buf[36] = (dstPort >> 8) & 0xff;
  buf[37] = dstPort & 0xff;
  const udpLen = 8 + payload.length;
  buf[38] = (udpLen >> 8) & 0xff;
  buf[39] = udpLen & 0xff;
  buf.set(payload, 42);
  return buf;
}

/** IPv4 fragment of a UDP datagram (payload starts at L4). */
function buildIpv4UdpFragment(opts: {
  srcIp: number[];
  dstIp: number[];
  identification: number;
  fragmentOffset: number;
  moreFragments: boolean;
  l4Bytes: Uint8Array;
}): Uint8Array {
  const { srcIp, dstIp, identification, fragmentOffset, moreFragments, l4Bytes } = opts;
  const total = 14 + 20 + l4Bytes.length;
  const buf = new Uint8Array(total);
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
  buf[12] = 0x08;
  buf[13] = 0x00;
  buf[14] = 0x45;
  const ipTotalLen = 20 + l4Bytes.length;
  buf[16] = (ipTotalLen >> 8) & 0xff;
  buf[17] = ipTotalLen & 0xff;
  buf[18] = (identification >> 8) & 0xff;
  buf[19] = identification & 0xff;
  const foUnits = fragmentOffset / 8;
  buf[20] = ((moreFragments ? 0x20 : 0) | ((foUnits >> 8) & 0x1f));
  buf[21] = foUnits & 0xff;
  buf[23] = 17;
  buf.set(srcIp, 26);
  buf.set(dstIp, 30);
  buf.set(l4Bytes, 34);
  return buf;
}

function envelope(data: Uint8Array, index = 0): PacketEnvelope {
  return {
    packetNumber: index,
    timestamp: { ticks: BigInt(index) * 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 24,
    data,
  };
}

function sipInvite(callId = 'cf04-call@host'): Uint8Array {
  return latin1([
    'INVITE sip:alice@192.168.1.10 SIP/2.0',
    'Via: SIP/2.0/TCP 192.168.1.10:5060;branch=z9hG4bK1',
    'From: <sip:alice@192.168.1.10>;tag=from-1',
    `Call-ID: ${callId}`,
    'Content-Length: 0',
    '',
    '',
  ].join('\r\n'));
}

function sipResponse(callId = 'cf04-call@host'): Uint8Array {
  return latin1([
    'SIP/2.0 200 OK',
    'Via: SIP/2.0/TCP 192.168.1.10:5060;branch=z9hG4bK1',
    'From: <sip:alice@192.168.1.10>;tag=from-1',
    `Call-ID: ${callId}`,
    'Content-Length: 0',
    '',
    '',
  ].join('\r\n'));
}

const limits = { ...DEFAULT_REASSEMBLY_LIMITS, maxConcurrentFlows: 32 };

describe('CF-04 directional TCP reassembly', () => {
  it('does not conflict when request and response share the same sequence number', () => {
    const req = sipInvite();
    const res = sipResponse();
    const tcp = new TcpStreamReassembler(limits);

    // Same seq in opposite directions — previously one bidirectional map → overlap-conflict
    tcp.ingest({
      packetIndex: 0,
      endpoint: { srcIp: '192.168.1.10', dstIp: '10.0.0.2', srcPort: 5060, dstPort: 5060, ipProto: 6 },
      seq: 1000,
      payloadOffset: 0,
      payloadLength: req.length,
      syn: false, fin: false, rst: false, isFragment: false,
    });
    tcp.ingest({
      packetIndex: 1,
      endpoint: { srcIp: '10.0.0.2', dstIp: '192.168.1.10', srcPort: 5060, dstPort: 5060, ipProto: 6 },
      seq: 1000,
      payloadOffset: 0,
      payloadLength: res.length,
      syn: false, fin: false, rst: false, isFragment: false,
    });

    const data = [req, res];
    const views = tcp.assembleAll(data);
    expect(views.length).toBe(2);
    expect(views.every((v) => v.status === 'complete')).toBe(true);
    expect(views.some((v) => new TextDecoder('latin1').decode(v.bytes).startsWith('INVITE'))).toBe(true);
    expect(views.some((v) => new TextDecoder('latin1').decode(v.bytes).startsWith('SIP/2.0 200'))).toBe(true);
    expect(views.some((v) => v.status === 'overlap-conflict')).toBe(false);
  });

  it('isolates conflict to one direction only', () => {
    const tcp = new TcpStreamReassembler(limits);
    const a = latin1('AAAA');
    const b = latin1('BBBB');
    const ok = sipInvite();

    tcp.ingest({
      packetIndex: 0,
      endpoint: { srcIp: '1.1.1.1', dstIp: '2.2.2.2', srcPort: 5060, dstPort: 5060, ipProto: 6 },
      seq: 10, payloadOffset: 0, payloadLength: 4,
      syn: false, fin: false, rst: false, isFragment: false,
    });
    tcp.ingest({
      packetIndex: 1,
      endpoint: { srcIp: '1.1.1.1', dstIp: '2.2.2.2', srcPort: 5060, dstPort: 5060, ipProto: 6 },
      seq: 10, payloadOffset: 0, payloadLength: 4,
      syn: false, fin: false, rst: false, isFragment: false,
    });
    tcp.ingest({
      packetIndex: 2,
      endpoint: { srcIp: '2.2.2.2', dstIp: '1.1.1.1', srcPort: 5060, dstPort: 5060, ipProto: 6 },
      seq: 50, payloadOffset: 0, payloadLength: ok.length,
      syn: false, fin: false, rst: false, isFragment: false,
    });

    const views = tcp.assembleAll([a, b, ok]);
    const forward = views.find((v) => v.flowKey.includes('1.1.1.1:5060->2.2.2.2:5060'));
    const reverse = views.find((v) => v.flowKey.includes('2.2.2.2:5060->1.1.1.1:5060'));
    expect(forward?.status).toBe('overlap-conflict');
    expect(reverse?.status).toBe('complete');
  });
});

describe('CF-05 off-port SIP and IP fragment unwrap', () => {
  it('reassembles segmented SIP/TCP on port 5070', () => {
    const full = sipInvite('off-port-5070@host');
    const mid = Math.floor(full.length / 2);
    const packets = [
      envelope(buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5070, 5070, 1000, full.subarray(0, mid)), 0),
      envelope(buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], 5070, 5070, 1000 + mid, full.subarray(mid)), 1),
    ];

    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY);
    const complete = reassembly.views.filter((v) => v.status === 'complete');
    expect(complete.length).toBeGreaterThan(0);
    expect(new TextDecoder('latin1').decode(complete[0]!.bytes)).toContain('Call-ID: off-port-5070@host');

    const discovery = runDiscoveryPipeline(packets, DIAGNOSTIC_POLICY, 'gen', 'offport.pcap', {
      reassemblyContext: reassembly,
    });
    const callIds = discovery.intents.filter(
      (i) => i.kind === 'entity-replacement' && i.category === 'sip-call-id',
    );
    expect(callIds.length).toBeGreaterThan(0);
  });

  it('PF-08: many off-port SIP promotions scale with the capture, not with capture size squared', () => {
    const packets: PacketEnvelope[] = [];
    let idx = 0;
    const noise = () => {
      packets.push(envelope(buildEthIpUdp([10, 1, 2, 3], [10, 4, 5, 6], 40000, 9000, latin1('noise-packet')), idx++));
    };

    // Interleave 40 distinct off-port SIP flows (each on its own port, each split across two
    // TCP segments so promotion happens mid-stream) with a lot of unrelated noise packets in
    // between. Before PF-08, each promotion re-parsed every packet seen so far in the whole
    // capture; with 40 promotions against a growing packet list that was the O(n^2) cliff.
    const flowCount = 40;
    const noisePerGap = 150;
    for (let f = 0; f < flowCount; f++) {
      const port = 6000 + f;
      const full = sipInvite(`pf08-call-${f}@host`);
      const mid = Math.floor(full.length / 2);
      for (let n = 0; n < noisePerGap; n++) noise();
      packets.push(envelope(buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], port, port, 1000, full.subarray(0, mid)), idx++));
      for (let n = 0; n < noisePerGap; n++) noise();
      packets.push(envelope(buildEthIpTcp([192, 168, 1, 10], [10, 0, 0, 2], port, port, 1000 + mid, full.subarray(mid)), idx++));
    }

    const start = performance.now();
    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY);
    const elapsed = performance.now() - start;

    const complete = reassembly.views.filter((v) => v.status === 'complete');
    expect(complete.length).toBe(flowCount);
    // ~12,800 packets, 40 promotions. O(n^2) re-walk here is tens of millions of re-parses;
    // O(n) is trivial. The bound is generous but unreachable under the old behavior.
    expect(elapsed).toBeLessThan(1000);
  });

  it('unwraps UDP header from IPv4-fragmented SIP before parsing', () => {
    const sip = sipInvite('frag-udp@host');
    const udpHeader = new Uint8Array(8);
    udpHeader[0] = 0x13; udpHeader[1] = 0xc4; // 5060
    udpHeader[2] = 0x13; udpHeader[3] = 0xc4;
    const udpLen = 8 + sip.length;
    udpHeader[4] = (udpLen >> 8) & 0xff;
    udpHeader[5] = udpLen & 0xff;
    const l4 = new Uint8Array(8 + sip.length);
    l4.set(udpHeader, 0);
    l4.set(sip, 8);

    const mid = Math.floor(l4.length / 2);
    // Align fragment offset to 8-byte boundary
    const split = mid - (mid % 8);
    const part1 = l4.subarray(0, split);
    const part2 = l4.subarray(split);

    const packets = [
      envelope(buildIpv4UdpFragment({
        srcIp: [192, 168, 1, 10],
        dstIp: [10, 0, 0, 2],
        identification: 0x4242,
        fragmentOffset: 0,
        moreFragments: true,
        l4Bytes: part1,
      }), 0),
      envelope(buildIpv4UdpFragment({
        srcIp: [192, 168, 1, 10],
        dstIp: [10, 0, 0, 2],
        identification: 0x4242,
        fragmentOffset: split,
        moreFragments: false,
        l4Bytes: part2,
      }), 1),
    ];

    const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY);
    const complete = reassembly.views.filter((v) => v.status === 'complete' && v.transport === 'udp');
    expect(complete.length).toBe(1);
    const text = new TextDecoder('latin1').decode(complete[0]!.bytes);
    expect(text.startsWith('INVITE')).toBe(true);
    expect(text).toContain('frag-udp@host');
    expect(text.charCodeAt(0)).not.toBe(0x13); // not UDP header bytes
  });

  it('IpFragmentReassembler exposes ipProto and unwrap strips UDP', () => {
    const sip = latin1('OPTIONS sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const udp = new Uint8Array(8 + sip.length);
    udp[4] = ((8 + sip.length) >> 8) & 0xff;
    udp[5] = (8 + sip.length) & 0xff;
    udp.set(sip, 8);

    const frag = new IpFragmentReassembler(limits);
    frag.ingestIpv4({
      packetIndex: 0,
      srcIp: '1.1.1.1',
      dstIp: '2.2.2.2',
      ipProto: 17,
      identification: 1,
      fragmentOffset: 0,
      moreFragments: false,
      payloadOffset: 0,
      payloadLength: udp.length,
    });
    const views = frag.assembleAll([udp]);
    expect(views[0]!.ipProto).toBe(17);
    const unwrapped = unwrapTransportDatagram(views[0]!);
    expect(unwrapped).not.toBeNull();
    expect(new TextDecoder('latin1').decode(unwrapped!.bytes).startsWith('OPTIONS')).toBe(true);
  });
});
