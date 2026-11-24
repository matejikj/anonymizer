/**
 * M-3 — DNS-SD (RFC 6763) service-type labels (_service._proto, e.g. "_http._tcp",
 * "_csco-sb-vsdp._mdns._udp") must survive anonymization: they're protocol/service
 * identifiers, not personal identities, and losing them destroys real diagnostic value
 * (e.g. "this is an mDNS Cisco VSDP announcement"). Only the leading instance-name label
 * should be pseudonymized.
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

/** A minimal DNS response with one ANSWER RR (type TXT) whose name is DNS-SD shaped. */
function buildDnsSdResponse(instanceLabel: string, serviceLabels: string[], domain: string): Uint8Array {
  const name = encodeDnsName([instanceLabel, ...serviceLabels, domain]);
  const txtValue = 'type=0';
  const rdata = [txtValue.length, ...Array.from(txtValue, (c) => c.charCodeAt(0))];
  const bytes = [
    0x00, 0x00, // transaction id
    0x80, 0x00, // flags: response
    0x00, 0x00, // QDCOUNT
    0x00, 0x01, // ANCOUNT
    0x00, 0x00, // NSCOUNT
    0x00, 0x00, // ARCOUNT
    ...name,
    0x00, 0x10, // TYPE = TXT (16)
    0x00, 0x01, // CLASS = IN
    0x00, 0x00, 0x00, 0x19, // TTL
    0x00, rdata.length, // RDLENGTH
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

describe('M-3 DNS-SD service-type preservation', () => {
  it('preserves _service._proto labels, only pseudonymizing the instance name', () => {
    const buf = buildDnsSdResponse('VSDPdba285', ['_csco-sb-vsdp', '_mdns', '_udp'], 'local');
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping();
    expect(sanitizeDns(buf, 0, buf.length, collector, mapping)).toBe(true);
    const out = applyPatches(buf, collector, mapping);
    const text = new TextDecoder('latin1').decode(out);

    expect(text).not.toContain('VSDPdba285');
    expect(text).toContain('_csco-sb-vsdp');
    expect(text).toContain('_mdns');
    expect(text).toContain('_udp');
  });

  it('still pseudonymizes an ordinary (non-DNS-SD) hostname fully', () => {
    const buf = buildDnsSdResponse('myworkstation', [], 'local');
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping();
    expect(sanitizeDns(buf, 0, buf.length, collector, mapping)).toBe(true);
    const out = applyPatches(buf, collector, mapping);
    const text = new TextDecoder('latin1').decode(out);

    expect(text).not.toContain('myworkstation');
  });
});
