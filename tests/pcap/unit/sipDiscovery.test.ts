import { describe, expect, it } from 'vitest';
import { MappingAuthority } from '../../../src/mapping/mappingAuthority';
import { aliasForConstraint } from '../../../src/mapping/mappingRegistry';
import {
  identitiesFromDiscovery,
  runDiscoveryPipeline,
} from '../../../src/pcap/discovery/discoveryPipeline';
import { discoverPacket } from '../../../src/pcap/discovery/discoverPacket';
import type { PacketEnvelope } from '../../../src/pcap/domain/types';
import { policyFromPreset } from '../../../src/pcap/sanitize/engine';
import { canonicalizeIdentity } from '../../../src/mapping/canonicalize';
import { classifySipPayload } from '../../../src/pcap/protocols/application/sip/classify';
import { parseSdpFromSipMessage } from '../../../src/pcap/protocols/application/sdp/attach';
import { extractSdpEntities } from '../../../src/pcap/protocols/application/sdp/extract';
import { IntentCollector } from '../../../src/pcap/discovery/intentCollector';
import { recordSipSdpDiscoveryIntents } from '../../../src/pcap/protocols/application/sip/discoverIntents';

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

describe('SIP/SDP discovery intents (step 6)', () => {
  it('attaches and extracts SDP media ports from a complete SIP message', () => {
    const sharedIp = '192.168.1.10';
    const payload = buildSipInviteWithSdp(sharedIp);
    const data = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, payload);
    const udpOffset = 34 + 8;
    const classified = classifySipPayload(data, udpOffset, payload.length, { portHint: true });
    expect(classified.kind).toBe('complete');
    if (classified.kind !== 'complete') return;

    const attached = parseSdpFromSipMessage(classified.message, data);
    expect(attached.kind).toBe('parsed');
    if (attached.kind !== 'parsed') return;
    expect(attached.sdp.kind).toBe('complete');
    if (attached.sdp.kind !== 'complete') return;

    const { entities } = extractSdpEntities(attached.sdp.session, data);
    expect(entities.some((e) => e.mappingCategory === 'port' && e.canonicalText === '54400')).toBe(true);
  });

  it('recordSipSdpDiscoveryIntents emits SDP media port intents', () => {
    const payload = buildSipInviteWithSdp('192.168.1.10');
    const data = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, payload);
    const udpOffset = 34 + 8;
    const classified = classifySipPayload(data, udpOffset, payload.length, { portHint: true });
    expect(classified.kind).toBe('complete');
    if (classified.kind !== 'complete') return;

    const intents = new IntentCollector();
    recordSipSdpDiscoveryIntents(intents, data, classified.message, 'udp', 0);
    expect(intents.intents.some(
      (i) => i.kind === 'entity-replacement' && i.category === 'port' && i.canonical === 'udp/54400',
    )).toBe(true);
  });

  it('records typed SIP entity-replacement intents during packet discovery', () => {
    const sharedIp = '192.168.1.10';
    const payload = buildSipInviteWithSdp(sharedIp);
    const data = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, payload);
    const policy = policyFromPreset('diagnostic');
    const discovered = discoverPacket(
      {
        index: 0,
        data,
        capturedLength: data.length,
        originalLength: data.length,
        linkType: 1,
      },
      0,
      policy,
    );

    const replacements = discovered.intents.filter((i) => i.kind === 'entity-replacement');
    const portIntents = replacements.filter((i) => i.category === 'port');
    expect(replacements.some((i) => i.category === 'sip-call-id')).toBe(true);
    expect(replacements.some((i) => i.category === 'sip-user')).toBe(true);
    expect(replacements.some((i) => i.category === 'sip-token')).toBe(true);
    expect(replacements.some((i) => i.category === 'ipv4' && i.canonical === sharedIp)).toBe(true);
    expect(portIntents.some((i) => i.canonical === 'udp/5060')).toBe(true);
    expect(portIntents.some((i) => i.canonical === 'udp/54400')).toBe(true);
    expect(replacements.some((i) => i.kind === 'fixed-redaction')).toBe(false);
  });

  it('resolves every discovery identity into the mapping snapshot (parity)', () => {
    const sharedIp = '192.168.1.10';
    const payload = buildSipInviteWithSdp(sharedIp);
    const data = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, payload);
    const packets = [envelopeFromPacket(data)];
    const policy = policyFromPreset('diagnostic');
    const discovery = runDiscoveryPipeline(packets, policy, 'gen', 'pcap');
    const identities = identitiesFromDiscovery(discovery);

    const authority = new MappingAuthority();
    const resolved = authority.resolve({
      generationId: 'gen',
      sourceId: 'pcap',
      identities,
    });
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;

    for (const id of identities) {
      const entry = resolved.snapshot.entries.find(
        (e) => e.category === id.category && e.canonical === id.canonical,
      );
      expect(entry, `${id.category}:${id.canonical}`).toBeDefined();
      expect(entry!.alias.length).toBeGreaterThan(0);
      expect(aliasForConstraint(entry!, id.constraint).length).toBeGreaterThan(0);
    }
  });

  it('shares the ipv4 wire alias across L3, SIP, SDP, and correlated text log', () => {
    const sharedIp = '192.168.1.10';
    const payload = buildSipInviteWithSdp(sharedIp);
    const data = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, payload);
    const packets = [envelopeFromPacket(data)];
    const policy = policyFromPreset('diagnostic');
    const discovery = runDiscoveryPipeline(packets, policy, 'gen', 'pcap');

    const authority = new MappingAuthority();
    const correlationOptions = { crossFormatLinking: true as const };
    const pcapIdentities = identitiesFromDiscovery(discovery);
    expect(
      authority.resolve({
        generationId: 'gen',
        sourceId: 'pcap',
        identities: pcapIdentities,
        correlationOptions,
      }).ok,
    ).toBe(true);

    const textCanonical = canonicalizeIdentity('ip', sharedIp)!;
    expect(
      authority.resolve({
        generationId: 'gen',
        sourceId: 'text',
        identities: [{
          category: 'ip',
          canonical: textCanonical,
          constraint: { kind: 'text-ascii', byteLength: sharedIp.length },
        }],
        correlationOptions,
      }).ok,
    ).toBe(true);

    const snapshot = authority.getPublishedSnapshot()!;
    const reg = authority.getRegistry().entries().find((e) => e.canonical === sharedIp)!;
    const wireAlias = aliasForConstraint(reg, { kind: 'ipv4-wire' });
    const textAlias = aliasForConstraint(reg, { kind: 'text-ascii', byteLength: sharedIp.length });

    const ipv4IntentCount = discovery.intents.filter(
      (i) => i.kind === 'entity-replacement' && i.category === 'ipv4' && i.canonical === sharedIp,
    ).length;
    expect(ipv4IntentCount).toBeGreaterThanOrEqual(3);

    expect(wireAlias).not.toBe(sharedIp);
    expect(textAlias).not.toBe(sharedIp);
    expect(textAlias).toBe(wireAlias);
    expect(snapshot.entries.some((e) => e.canonical === sharedIp && e.aliases.length >= 2)).toBe(true);
  });

  it('canonicalizes sip-phone from tel URI for text-category sharing', () => {
    const payload = latin1('INVITE tel:+420777123456 SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const data = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, payload);
    const discovery = runDiscoveryPipeline(
      [envelopeFromPacket(data)],
      policyFromPreset('diagnostic'),
      'gen',
      'pcap',
    );

    const phoneIntent = discovery.intents.find(
      (i) => i.kind === 'entity-replacement' && i.category === 'sip-phone',
    );
    expect(phoneIntent).toBeDefined();
    expect(phoneIntent!.canonical).toBe('+420777123456');

    const authority = new MappingAuthority();
    const correlationOptions = { crossFormatLinking: true as const };
    authority.resolve({
      generationId: 'gen',
      sourceId: 'pcap',
      identities: identitiesFromDiscovery(discovery),
      correlationOptions,
    });
    authority.resolve({
      generationId: 'gen',
      sourceId: 'text',
      identities: [{
        category: 'sip-phone',
        canonical: '+420777123456',
        constraint: { kind: 'text-ascii', byteLength: 13 },
        originalSpelling: '+420777123456',
      }],
      correlationOptions,
    });

    const entry = authority.getPublishedSnapshot()!.entries.find(
      (e) => e.category === 'sip-phone' && e.canonical === '+420777123456',
    );
    expect(entry).toBeDefined();
    expect(entry!.alias).not.toContain('777');
  });
});
