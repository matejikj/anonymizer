/**
 * CF-01 acceptance tests — SIP/SDP sensitive value leaks (P0 security).
 */

import { describe, expect, it } from 'vitest';
import {
  applySipRedactionPlan,
  buildSipRedactionPlan,
  decodeLatin1Span,
  extractSipEntities,
  isCredentialEntity,
  parseSipMessage,
  type ByteSpan,
} from '../../../src/pcap/protocols/application/sip';
import {
  applySdpRedactionPlan,
  buildSdpRedactionPlan,
  DEFAULT_SDP_PARSE_LIMITS,
  extractSdpEntities,
  parseSdp,
  parseSdpFromSipMessage,
} from '../../../src/pcap/protocols/application/sdp';

function latin1(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

function spanText(buf: Uint8Array, span: ByteSpan): string {
  return decodeLatin1Span(buf, span);
}

function parseComplete(buf: Uint8Array) {
  const result = parseSipMessage(buf);
  if (result.kind !== 'complete') {
    const reason = result.kind === 'not-sip' || result.kind === 'malformed' || result.kind === 'incomplete'
      ? result.reason
      : result.kind;
    throw new Error(`expected complete parse, got ${result.kind}: ${reason}`);
  }
  return result.message;
}

function redactSip(buf: Uint8Array) {
  const message = parseComplete(buf);
  const { entities } = extractSipEntities(message, buf);
  const plan = buildSipRedactionPlan(entities);
  return applySipRedactionPlan(buf, plan);
}

function redactSipSdp(buf: Uint8Array) {
  const message = parseComplete(buf);
  const { entities: sipEntities } = extractSipEntities(message, buf);
  const ops = [...buildSipRedactionPlan(sipEntities).operations];
  const attached = parseSdpFromSipMessage(message, buf);
  if (attached.kind === 'parsed' && attached.sdp.kind === 'complete') {
    const { entities: sdpEntities } = extractSdpEntities(attached.sdp.session, buf);
    ops.push(...buildSdpRedactionPlan(sdpEntities).operations);
  }
  ops.sort((a, b) => a.span.offset - b.span.offset);
  return applySipRedactionPlan(buf, { operations: ops });
}

function expectNoLeak(text: string, secrets: readonly string[]) {
  for (const secret of secrets) {
    expect(text, `leaked ${secret}`).not.toContain(secret);
  }
}

describe('CF-01 SIP/SDP leak fixes', () => {
  it('redacts unquoted display name in From', () => {
    const secret = 'Alice Smith';
    const buf = latin1([
      'INVITE sip:bob@example SIP/2.0\r\n',
      `From: ${secret} <sip:alice@corp.example>;tag=1\r\n`,
      'Content-Length: 0\r\n\r\n',
    ].join(''));
    const { entities } = extractSipEntities(parseComplete(buf), buf);
    expect(entities.some((e) => e.kind === 'display-name' && e.canonicalText === secret)).toBe(true);
    const out = new TextDecoder('latin1').decode(redactSip(buf));
    expectNoLeak(out, [secret, 'alice@corp.example']);
  });

  it('redacts unknown Digest auth parameters (deny-by-default)', () => {
    const secret = 'UnknownSecret42';
    const buf = latin1([
      'REGISTER sip:r SIP/2.0\r\n',
      `Authorization: Digest foo="${secret}"\r\n`,
      'Content-Length: 0\r\n\r\n',
    ].join(''));
    const { entities } = extractSipEntities(parseComplete(buf), buf);
    const cred = entities.filter(isCredentialEntity);
    expect(cred.some((e) => e.parameterName === 'foo')).toBe(true);
    const out = new TextDecoder('latin1').decode(redactSip(buf));
    expectNoLeak(out, [secret]);
    expect(out).toContain('foo=');
  });

  it('extracts branch parameter from folded Via continuation', () => {
    const branch = 'z9hG4bKfolded-secret-branch';
    const buf = latin1([
      'INVITE sip:a@b SIP/2.0\r\n',
      'Via: SIP/2.0/UDP 1.1.1.1:5060;\r\n',
      ` branch=${branch}\r\n`,
      'Content-Length: 0\r\n\r\n',
    ].join(''));
    const message = parseComplete(buf);
    const via = message.headers.find((h) => h.canonicalNameText === 'via')!;
    expect(via.parameters.some((p) => spanText(buf, p.name).toLowerCase() === 'branch')).toBe(true);
    const { entities } = extractSipEntities(message, buf);
    expect(entities.some((e) => e.parameterName === 'branch' && e.canonicalText === branch)).toBe(true);
    const out = new TextDecoder('latin1').decode(redactSip(buf));
    expectNoLeak(out, [branch]);
  });

  it('redacts SDP remote-candidates, candidate raddr/rport, and RTCP address', () => {
    const remoteAddr = '203.0.113.50';
    const raddr = '198.51.100.77';
    const rtcpAddr = '192.0.2.15';
    const sdp = [
      'v=0',
      'o=- 0 0 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 49170 RTP/AVP 0',
      `a=remote-candidates:1 ${remoteAddr} 49172`,
      `a=candidate:1 1 UDP 2130706431 10.0.0.1 49170 typ host raddr ${raddr} rport 9`,
      `a=rtcp:53020 IN IP4 ${rtcpAddr}`,
    ].join('\r\n');
    const buf = latin1([
      'INVITE sip:a@b SIP/2.0\r\n',
      'Content-Type: application/sdp\r\n',
      `Content-Length: ${sdp.length}\r\n`,
      '\r\n',
      sdp,
    ].join(''));
    const message = parseComplete(buf);
    const attached = parseSdpFromSipMessage(message, buf);
    expect(attached.kind).toBe('parsed');
    if (attached.kind !== 'parsed' || attached.sdp.kind !== 'complete') throw new Error('sdp parse failed');
    const { entities } = extractSdpEntities(attached.sdp.session, buf);
    expect(entities.some((e) => e.field === 'a.remote-candidates.address')).toBe(true);
    expect(entities.some((e) => e.field === 'a.candidate.raddr')).toBe(true);
    expect(entities.some((e) => e.field === 'a.rtcp.address')).toBe(true);
    const out = new TextDecoder('latin1').decode(redactSipSdp(buf));
    expectNoLeak(out, [remoteAddr, raddr, rtcpAddr]);
  });

  it('fails closed when attribute limit is exceeded (ICE pwd beyond limit)', () => {
    const secretPwd = 'IcePwdBeyondLimitSecret';
    const limit = 2;
    const lines = [
      'v=0',
      'o=- 0 0 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 49170 RTP/AVP 0',
    ];
    for (let i = 0; i < limit; i++) {
      lines.push(`a=fmtp:${i} 0`);
    }
    lines.push(`a=ice-pwd:${secretPwd}`);
    const sdp = lines.join('\r\n');
    const buf = latin1(sdp);
    const result = parseSdp(buf, {
      limits: { ...DEFAULT_SDP_PARSE_LIMITS, maxAttributesPerSection: limit },
    });
    expect(result.kind).toBe('malformed');
    if (result.kind === 'malformed') {
      expect(result.reason).toBe('attribute-limit');
    }
  });
});
