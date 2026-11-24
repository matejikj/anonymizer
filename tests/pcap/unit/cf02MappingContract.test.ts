/**
 * CF-02 acceptance — constraint-aware aliases and length-stable text patches.
 */

import { describe, expect, it } from 'vitest';
import {
  sanitizePacket,
  DIAGNOSTIC_POLICY,
  type PacketInput,
} from '../../../src/pcap/sanitize';
import { SessionMapping, DEFAULT_MAPPING_CONFIG } from '../../../src/pcap/anonymization/mapping';
import { SnapshotMappingAdapter } from '../../../src/pcap/plan/snapshotMappingAdapter';
import {
  formatPortTextFromWire,
  maskDigitsPreservingFormat,
} from '../../../src/pcap/anonymization/wireTextFormat';
import { patchFixedLengthAscii } from '../../../src/pcap/sanitize/textPatch';
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector';

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0)));
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
  buf[34] = (srcPort >> 8) & 0xff;
  buf[35] = srcPort & 0xff;
  buf[36] = (dstPort >> 8) & 0xff;
  buf[37] = dstPort & 0xff;
  buf.set(payload, 42);
  return buf;
}

function applyExport(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const len = result.truncatedLength ?? original.length;
  const out = original.slice(0, len);
  for (const patch of result.patches) {
    if (patch.offset < len) out.set(patch.data.slice(0, len - patch.offset), patch.offset);
  }
  return out;
}

describe('CF-02 mapping contract', () => {
  it('preserves phone delimiters (+420-123-456)', () => {
    const original = '+420-123-456';
    const mapped = maskDigitsPreservingFormat(original, '900000001234');
    expect(mapped.length).toBe(original.length);
    expect(mapped[0]).toBe('+');
    expect(mapped).toContain('-');
    expect(mapped).not.toContain('123');
  });

  it('preserves port digit width in SIP text', () => {
    const mapping = new SessionMapping();
    const wire = mapping.map('port', 'udp/49152');
    const slash = wire.indexOf('/');
    const mappedPort = Number.parseInt(wire.slice(slash + 1), 10);
    const text = formatPortTextFromWire(mappedPort, '49152');
    expect(text.length).toBe(5);
    expect(text).not.toBe('4915');
  });

  it('uses same numeric port in L4 and SIP text after sanitization', () => {
    const sharedIp = '192.168.42.99';
    const body = [
      `INVITE sip:user@${sharedIp}:54400 SIP/2.0`,
      `Via: SIP/2.0/UDP ${sharedIp}:54400;branch=z9hG4bK1`,
      'Content-Length: 0',
      '',
      '',
    ].join('\r\n');
    const payload = latin1(body);
    const pkt = buildEthIpUdp([192, 168, 42, 99], [10, 0, 0, 2], 54400, 5060, payload);
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' });
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    const exported = applyExport(pkt, result);
    const text = new TextDecoder('latin1').decode(exported.slice(42));
    expect(text).not.toContain('54400');
    expect(text).not.toContain('192.168.42.99');
    const l4SrcPort = (exported[34]! << 8) | exported[35]!;
    const mappedWire = mapping.map('port', 'udp/54400');
    const mappedPortNum = Number.parseInt(mappedWire.split('/')[1]!, 10);
    expect(l4SrcPort).toBe(mappedPortNum);
    const textAlias = mapping.aliasFor(
      'port',
      'udp/54400',
      { kind: 'text-ascii', byteLength: 5 },
      '54400',
    );
    expect(text).toContain(`:${textAlias}`);
  });

  it('SnapshotMappingAdapter derives text alias from wire when constraint alias missing', () => {
    const adapter = new SnapshotMappingAdapter({
      scope: 'request',
      revision: 1,
      mappingRevision: 1,
      canonicalizationVersion: 1,
      generationId: 'g',
      sourceId: 's',
      overflow: false,
      entries: [{
        identityId: 1,
        category: 'ipv4',
        canonical: '10.0.0.1',
        alias: '198.51.100.10',
        aliases: [{
          alias: '198.51.100.10',
          constraint: { kind: 'ipv4-wire' },
          disposition: 'bijective',
        }],
        constraint: { kind: 'ipv4-wire' },
        disposition: 'bijective',
        occurrenceCount: 1,
      }],
    });
    const alias = adapter.aliasFor('ipv4', '10.0.0.1', { kind: 'text-ascii', byteLength: 8 });
    expect(alias.length).toBe(8);
    expect(alias).not.toBe('10.0.0.1');
    expect(alias).not.toBe('198.51.100.10');
  });

  it('SnapshotMappingAdapter canonicalizes mixed-case hostname lookups', () => {
    const adapter = new SnapshotMappingAdapter({
      scope: 'request',
      revision: 1,
      mappingRevision: 1,
      canonicalizationVersion: 1,
      generationId: 'g',
      sourceId: 's',
      overflow: false,
      entries: [{
        identityId: 1,
        category: 'hostname',
        canonical: 'sep204c9eb352ab',
        alias: 'hostalias000001',
        aliases: [{
          alias: 'hostalias000001',
          constraint: { kind: 'text-ascii', byteLength: 15 },
          disposition: 'bijective',
        }],
        constraint: { kind: 'text-ascii', byteLength: 15 },
        disposition: 'bijective',
        occurrenceCount: 1,
      }],
    });
    expect(adapter.map('hostname', 'SEP204C9EB352AB')).toBe('hostalias000001');
  });

  it('patchFixedLengthAscii rejects silent truncation', () => {
    const collector = new PatchCollector(32);
    expect(() => patchFixedLengthAscii(collector, 0, 10, '198.51.')).toThrow(/length/i);
  });
});
