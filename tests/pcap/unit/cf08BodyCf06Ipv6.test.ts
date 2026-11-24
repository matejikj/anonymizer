/**
 * CF-08 / CF-06 acceptance — SIP body fail-closed coverage and bracketed IPv6 URI.
 */

import { describe, expect, it } from 'vitest';
import {
  sanitizePacket,
  DIAGNOSTIC_POLICY,
  type PacketInput,
} from '../../../src/pcap/sanitize';
import { SessionMapping } from '../../../src/pcap/anonymization/mapping';
import {
  decodeLatin1Span,
  DEFAULT_SIP_PARSE_LIMITS,
  parseSipUri,
} from '../../../src/pcap/protocols/application/sip';
import {
  extractSdpEntities,
  parseSdp,
} from '../../../src/pcap/protocols/application/sdp';
import { decideSipBodyPolicy } from '../../../src/pcap/protocols/application/sip/bodyPolicy';
import { parseSipMessage } from '../../../src/pcap/protocols/application/sip';

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

function applyExport(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const len = result.truncatedLength ?? original.length;
  const out = original.slice(0, len);
  for (const patch of result.patches) {
    if (patch.offset < len) out.set(patch.data.slice(0, len - patch.offset), patch.offset);
  }
  return out;
}

describe('CF-08 SIP body policy', () => {
  it('redacts text/plain body and marks sip-body as redacted, not covered', () => {
    const secret = 'SecretPhone+420123456789';
    const body = `Please call ${secret} urgently.`;
    const sip = [
      'MESSAGE sip:bob@example SIP/2.0',
      'From: <sip:alice@example>;tag=1',
      'To: <sip:bob@example>',
      'Call-ID: body-cf08@example',
      'Content-Type: text/plain',
      `Content-Length: ${body.length}`,
      '',
      body,
    ].join('\r\n');
    const payload = latin1(sip);
    const pkt = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, payload);
    const mapping = new SessionMapping();
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    expect(result.coverage.some((c) => c.protocol === 'sip' && c.status === 'covered')).toBe(true);
    expect(result.coverage.some((c) => c.protocol === 'sip-body' && c.status === 'redacted')).toBe(true);
    expect(result.coverage.some((c) => c.protocol === 'sip' && c.length === payload.length && c.status === 'covered')).toBe(false);

    const exported = applyExport(pkt, result);
    const text = new TextDecoder('latin1').decode(exported);
    expect(text).not.toContain(secret);
    expect(text).toContain('Content-Type: text/plain');
  });

  it('decideSipBodyPolicy marks missing content-type body as unsupported', () => {
    const sip = latin1([
      'MESSAGE sip:bob@example SIP/2.0\r\n',
      'Content-Length: 5\r\n\r\n',
      'hello',
    ].join(''));
    const parsed = parseSipMessage(sip);
    expect(parsed.kind).toBe('complete');
    if (parsed.kind !== 'complete') return;
    const decision = decideSipBodyPolicy(parsed.message, sip);
    expect(decision.kind).toBe('unsupported');
    expect(decision.reason).toBe('missing-content-type');
  });

  it('redacts SDP metadata lines and unknown attributes', () => {
    const secretSession = 'SecretSessionName';
    const secretAttr = 'x-secret-token-99';
    const sdp = [
      'v=0',
      'o=- 1 2 IN IP4 10.0.0.1',
      `s=${secretSession}`,
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'k=clear:SuperSecretKey',
      'm=audio 5004 RTP/AVP 0',
      `a=${secretAttr}:value-should-go`,
    ].join('\r\n');
    const parsed = parseSdp(latin1(sdp));
    expect(parsed.kind).toBe('complete');
    if (parsed.kind !== 'complete') return;
    const { entities } = extractSdpEntities(parsed.session, latin1(sdp));
    expect(entities.some((e) => e.kind === 'metadata-text' && e.field === 's.value')).toBe(true);
    expect(entities.some((e) => e.kind === 'metadata-text' && e.field === 'k.value')).toBe(true);
    expect(entities.some((e) => e.kind === 'unknown-attribute')).toBe(true);
  });
});

describe('CF-06 bracketed IPv6 SIP URI', () => {
  it('parses host interior without brackets and numeric port', () => {
    const uri = 'sip:alice@[2001:db8:dead:beef::1234]:5060';
    const buf = latin1(uri);
    const result = parseSipUri(buf, 0, buf.length, DEFAULT_SIP_PARSE_LIMITS);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(decodeLatin1Span(buf, result.uri.host)).toBe('2001:db8:dead:beef::1234');
    expect(result.uri.port).not.toBeNull();
    expect(decodeLatin1Span(buf, result.uri.port!)).toBe('5060');
    expect(decodeLatin1Span(buf, result.uri.user!)).toBe('alice');
  });

  it('rejects missing closing bracket', () => {
    const uri = 'sip:alice@[2001:db8::1:5060';
    const buf = latin1(uri);
    const result = parseSipUri(buf, 0, buf.length, DEFAULT_SIP_PARSE_LIMITS);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('uri-ipv6-bracket');
  });

  it('rejects non-numeric port after bracketed host', () => {
    const uri = 'sip:alice@[2001:db8::1]:abcd';
    const buf = latin1(uri);
    const result = parseSipUri(buf, 0, buf.length, DEFAULT_SIP_PARSE_LIMITS);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('uri-port-nonnumeric');
  });

  it('anonymizes IPv6 URI without leaking hextets as hostname truncation', () => {
    // NB: deliberately not in the 2001:db8::/32 RFC 3849 documentation range — that prefix is
    // also this tool's own fixed pseudonym prefix for public IPv6 addresses (by design: it's
    // reserved for exactly this "obviously an example/anonymized address" purpose), so an
    // original address using it here could spuriously collide with a correctly-generated
    // pseudonym and make the assertions below pass or fail by luck rather than by correctness.
    const v6 = '2001:4998:dead:beef::1234';
    const sip = [
      `INVITE sip:alice@[${v6}]:5060 SIP/2.0`,
      `Via: SIP/2.0/UDP [${v6}]:5060;branch=z9hG4bK1`,
      `From: <sip:alice@[${v6}]>;tag=1`,
      'Content-Length: 0',
      '',
      '',
    ].join('\r\n');
    const payload = latin1(sip);
    const pkt = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5060, 5060, payload);
    // Put IPv6 in L3 would need IPv6 packet; here we only assert SIP text rewrite.
    const mapping = new SessionMapping();
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);
    const exported = applyExport(pkt, result);
    const text = new TextDecoder('latin1').decode(exported);
    expect(text).not.toContain('dead:beef');
    expect(text).not.toContain('2001:4998');
    expect(text).toMatch(/sip:[^@]+@\[[^\]]+\]:\d+/i);
    expect(text).toContain(']>;tag=');
    expect(text).toContain(']:5060;branch=');
  });
});
