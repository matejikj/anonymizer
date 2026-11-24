/**
 * Bonus-1 (structural TXT sub-record framing) + VLAN-in-TXT leak fix: a DNS/mDNS TXT RR's
 * [1-byte length][string] sub-records must never be treated as one opaque blob (corrupts the
 * length-prefix bytes — see dtPcapRegressionGate's real dt.pcap "mDNS Malformed Packet" find),
 * and a "voice-vlan-id=<N>" value must go through the same VLAN mapping as the 802.1Q tag
 * rather than being preserved as benign diagnostic data (it's the same sensitive VLAN number).
 */

import { describe, expect, it } from 'vitest';
import { sanitizeDns } from '../../../src/pcap/sanitize/dns';
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector';
import { SessionMapping } from '../../../src/pcap/anonymization/mapping';

function encodeDnsName(labels: string[]): number[] {
  const bytes: number[] = [];
  for (const label of labels) {
    bytes.push(label.length);
    for (const ch of label) bytes.push(ch.charCodeAt(0));
  }
  bytes.push(0);
  return bytes;
}

function txtSubrecord(value: string): number[] {
  return [value.length, ...Array.from(value, (c) => c.charCodeAt(0))];
}

/** A minimal DNS response with one ANSWER RR (type TXT) carrying several sub-records. */
function buildTxtResponse(name: string[], values: string[]): Uint8Array {
  const rdata = values.flatMap(txtSubrecord);
  const bytes = [
    0x00, 0x00, // transaction id
    0x80, 0x00, // flags: response
    0x00, 0x00, // QDCOUNT
    0x00, 0x01, // ANCOUNT
    0x00, 0x00, // NSCOUNT
    0x00, 0x00, // ARCOUNT
    ...encodeDnsName(name),
    0x00, 0x10, // TYPE = TXT (16)
    0x00, 0x01, // CLASS = IN
    0x00, 0x00, 0x00, 0x19, // TTL
    (rdata.length >> 8) & 0xff, rdata.length & 0xff, // RDLENGTH
    ...rdata,
  ];
  return new Uint8Array(bytes);
}

function applyPatches(buf: Uint8Array, collector: PatchCollector, mapping: SessionMapping): Uint8Array {
  const out = buf.slice();
  collector.resolveDeferred({ mapping });
  for (const patch of collector.getPatches()) out.set(patch.data, patch.offset);
  return out;
}

describe('DNS TXT sub-record framing', () => {
  it('preserves each sub-record length prefix and benign key=value data', () => {
    const buf = buildTxtResponse(['device1', 'local'], ['type=0', 'priority=0', 'cost=0']);
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping();
    expect(sanitizeDns(buf, 0, buf.length, collector, mapping)).toBe(true);
    const out = applyPatches(buf, collector, mapping);
    const text = new TextDecoder('latin1').decode(out);

    expect(text).toContain('type=0');
    expect(text).toContain('priority=0');
    expect(text).toContain('cost=0');
  });

  it('substitutes an embedded MAC/IP without corrupting neighbouring sub-records', () => {
    const values = ['type=0', 'root-mac-address=88:f0:77:db:a2:85', 'transm-address=172.18.0.252', 'cost=0'];
    const buf = buildTxtResponse(['device1', 'local'], values);
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping();
    expect(sanitizeDns(buf, 0, buf.length, collector, mapping)).toBe(true);
    const out = applyPatches(buf, collector, mapping);
    const text = new TextDecoder('latin1').decode(out);

    expect(text).not.toContain('88:f0:77:db:a2:85');
    expect(text).not.toContain('172.18.0.252');
    // neighbouring benign sub-records must survive untouched
    expect(text).toContain('type=0');
    expect(text).toContain('cost=0');
  });

  it('routes voice-vlan-id through the VLAN mapping instead of preserving the raw number', () => {
    const buf = buildTxtResponse(['device1', 'local'], ['voice-vlan-id=111', 'cost=0']);
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping();
    expect(sanitizeDns(buf, 0, buf.length, collector, mapping)).toBe(true);
    const out = applyPatches(buf, collector, mapping);
    const text = new TextDecoder('latin1').decode(out);

    expect(text).not.toContain('voice-vlan-id=111');
    expect(text).toMatch(/voice-vlan-id=\d+/);
    expect(text).toContain('cost=0');
  });

  it('reuses the same session VLAN mapping as the 802.1Q tag (same cache entry, not a parallel scheme)', () => {
    // The text occurrence must still fit its own original byte length (same length-stable
    // contract as every other text-embedded identity in this codebase — e.g. IPv4 in SIP/SDP),
    // so it won't always be byte-identical to the wire-level mapped value when digit counts
    // differ. What matters is that it's driven by the SAME underlying mapping entry, not an
    // independent/inconsistent one.
    const mapping = new SessionMapping();
    const buf = buildTxtResponse(['device1', 'local'], ['voice-vlan-id=111']);
    const collector = new PatchCollector(buf.length);
    expect(sanitizeDns(buf, 0, buf.length, collector, mapping)).toBe(true);
    const out = applyPatches(buf, collector, mapping);
    const text = new TextDecoder('latin1').decode(out);

    const tagMapped = mapping.map('vlan', '111');
    expect(text).not.toContain('voice-vlan-id=111');
    const match = /voice-vlan-id=(\d+)/.exec(text);
    expect(match).toBeTruthy();
    // every digit of the text alias must come from the same mapped decimal value (cycled to
    // fit the original 3-digit width) — proves it's the same entry, not an unrelated value.
    for (let i = 0; i < match![1]!.length; i++) {
      expect(match![1]![i]).toBe(tagMapped[i % tagMapped.length]);
    }
  });
});
