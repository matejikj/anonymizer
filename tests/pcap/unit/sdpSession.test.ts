import { describe, expect, it } from 'vitest';
import {
  decodeLatin1Span,
  parseSipMessage,
  type ByteSpan,
} from '../../../src/pcap/protocols/application/sip';
import {
  applySdpRedactionPlan,
  buildSdpRedactionPlan,
  buildSdpMediaEndpoints,
  buildSdpSessionBundle,
  collectFlowKeys,
  DEFAULT_SDP_REDACTION_POLICY,
  extractSdpEntities,
  isSdpSecretEntity,
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

function sdpBody(lines: string[]): string {
  return `${lines.join('\r\n')}\r\n`;
}

describe('SDP parser and media model (step 5)', () => {
  it('parses session-level IPv4 connection and origin', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=jnovak 2890844526 2890844527 IN IP4 192.168.1.10',
      's=-',
      'c=IN IP4 192.168.1.10',
      't=0 0',
      'm=audio 49170 RTP/AVP 0',
    ]));

    const result = parseSdp(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;

    expect(result.session.origin).not.toBeNull();
    expect(spanText(buf, result.session.origin!.username)).toBe('jnovak');
    expect(spanText(buf, result.session.sessionConnection!.address)).toBe('192.168.1.10');
    expect(result.session.media).toHaveLength(1);
    expect(spanText(buf, result.session.media[0]!.port)).toBe('49170');
  });

  it('parses media-level IPv6 connection', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=- 0 0 IN IP6 2001:db8::1',
      's=-',
      't=0 0',
      'm=audio 5000 RTP/AVP 0',
      'c=IN IP6 2001:db8::2',
    ]));

    const result = parseSdp(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;

    expect(result.diagnostics.issues).not.toContain('malformed-media-c-line');
    expect(result.session.media[0]!.connection).not.toBeNull();
    expect(spanText(buf, result.session.media[0]!.connection!.address)).toBe('2001:db8::2');
    const endpoints = buildSdpMediaEndpoints(result.session, buf);
    expect(endpoints[0]!.address).toBe('2001:db8::2');
  });

  it('parses multiple m= sections with payload types', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=- 0 0 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 4000 RTP/AVP 0 8',
      'm=video 4002 RTP/AVP 96',
    ]));

    const result = parseSdp(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;

    expect(result.session.media).toHaveLength(2);
    expect(result.session.media[0]!.payloadTypes).toHaveLength(2);
    expect(result.session.media[1]!.payloadTypes).toHaveLength(1);
  });

  it('parses ICE, RTCP mux, fingerprint and crypto attributes', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=- 0 0 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 9 RTP/AVP 0',
      'a=rtcp:9',
      'a=rtcp-mux',
      'a=ice-ufrag:F7gI',
      'a=ice-pwd:abcdef123456',
      'a=fingerprint:sha-256 AB:CD:EF:00',
      'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:BASE64KEY',
      'a=candidate:1 1 UDP 2130706431 192.168.1.20 54400 typ host',
      'a=candidate:2 1 UDP 2130706431 192.168.1.21 54401 typ host',
    ]));

    const result = parseSdp(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;

    const media = result.session.media[0]!;
    const kinds = media.attributes.map((a) => a.kind);
    expect(kinds).toContain('rtcp');
    expect(kinds).toContain('rtcp-mux');
    expect(kinds).toContain('ice-ufrag');
    expect(kinds).toContain('ice-pwd');
    expect(kinds).toContain('fingerprint');
    expect(kinds).toContain('crypto');
    expect(kinds.filter((k) => k === 'candidate')).toHaveLength(2);
  });

  it('builds RTP/RTCP flow keys including ICE candidates', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=- 0 0 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 49170 RTP/AVP 0',
      'a=rtcp:49171',
      'a=candidate:1 1 UDP 2130706431 192.168.1.20 54400 typ host',
    ]));

    const result = parseSdp(buf);
    if (result.kind !== 'complete') throw new Error('parse failed');
    const endpoints = buildSdpMediaEndpoints(result.session, buf);
    const flows = collectFlowKeys(endpoints);

    expect(flows.some((f) => f.protocol === 'rtp' && f.port === 49170)).toBe(true);
    expect(flows.some((f) => f.protocol === 'rtcp' && f.port === 49171)).toBe(true);
    expect(flows.some((f) => f.ip === '192.168.1.20' && f.port === 54400)).toBe(true);
  });

  it('uses RTCP mux port equal to RTP when a=rtcp-mux is present', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=- 0 0 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 9 RTP/AVP 0',
      'a=rtcp-mux',
    ]));

    const result = parseSdp(buf);
    if (result.kind !== 'complete') throw new Error('parse failed');
    const endpoints = buildSdpMediaEndpoints(result.session, buf);
    expect(endpoints[0]!.rtcpPort).toBe(9);
  });

  it('records issues for missing o= / m= without failing the parse', () => {
    const buf = latin1(sdpBody(['v=0', 's=-', 't=0 0']));
    const result = parseSdp(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;

    const { issues } = extractSdpEntities(result.session, buf);
    expect(issues).toContain('missing-o-line');
    expect(issues).toContain('missing-m-section');
  });

  it('attaches SDP only when SIP Content-Type is application/sdp', () => {
    const sdp = sdpBody([
      'v=0',
      'o=- 0 0 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 4000 RTP/AVP 0',
    ]);
    const buf = latin1([
      'INVITE sip:a@b SIP/2.0\r\n',
      'Content-Type: application/sdp\r\n',
      'Content-Length: ',
      String(sdp.length),
      '\r\n\r\n',
      sdp,
    ].join(''));

    const sip = parseSipMessage(buf);
    expect(sip.kind).toBe('complete');
    if (sip.kind !== 'complete') return;

    const attached = parseSdpFromSipMessage(sip.message, buf);
    expect(attached.kind).toBe('parsed');
    if (attached.kind !== 'parsed') return;
    expect(attached.sdp.kind).toBe('complete');
  });

  it('rejects non-SDP SIP bodies by content type', () => {
    const buf = latin1([
      'INVITE sip:a@b SIP/2.0\r\n',
      'Content-Type: text/plain\r\n',
      'Content-Length: 4\r\n\r\n',
      'ping',
    ].join(''));
    const sip = parseSipMessage(buf);
    if (sip.kind !== 'complete') throw new Error('sip parse failed');
    const attached = parseSdpFromSipMessage(sip.message, buf);
    expect(attached.kind).toBe('no-sdp');
  });

  it('builds session bundle with Call-ID binding', () => {
    const sdp = sdpBody([
      'v=0',
      'o=- 0 0 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 4000 RTP/AVP 0',
    ]);
    const buf = latin1([
      'INVITE sip:a@b SIP/2.0\r\n',
      'Call-ID: dialog-1\r\n',
      'Content-Type: application/sdp\r\n',
      'Content-Length: ',
      String(sdp.length),
      '\r\n\r\n',
      sdp,
    ].join(''));

    const sip = parseSipMessage(buf);
    if (sip.kind !== 'complete') throw new Error('sip parse failed');
    const result = buildSdpSessionBundle(sip.message, buf);
    expect(result.kind).toBe('parsed');
    if (result.kind !== 'parsed' || !result.bundle) return;
    expect(result.bundle.callId).toBe('dialog-1');
    expect(result.bundle.endpoints[0]!.callId).toBe('dialog-1');
  });

  it('redacts ICE credentials and crypto while mapping addresses', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=- 0 0 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 9 RTP/AVP 0',
      'a=ice-ufrag:SECRETUFRAG',
      'a=ice-pwd:SECRETPASSWORD',
      'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:BASE64KEY',
    ]));

    const parsed = parseSdp(buf);
    if (parsed.kind !== 'complete') throw new Error('parse failed');
    const { entities } = extractSdpEntities(parsed.session, buf, { policy: DEFAULT_SDP_REDACTION_POLICY });

    expect(entities.filter(isSdpSecretEntity).every((e) => e.action === 'redact')).toBe(true);
    const plan = buildSdpRedactionPlan(entities);
    const redacted = applySdpRedactionPlan(buf, plan);
    const text = new TextDecoder('latin1').decode(redacted);
    expect(text).not.toContain('SECRETUFRAG');
    expect(text).not.toContain('SECRETPASSWORD');
    expect(text).not.toContain('BASE64KEY');
  });

  it('maps fingerprint when policy is map', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=- 0 0 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 9 RTP/AVP 0',
      'a=fingerprint:sha-256 AB:CD:EF:00',
    ]));

    const parsed = parseSdp(buf);
    if (parsed.kind !== 'complete') throw new Error('parse failed');
    const { entities } = extractSdpEntities(parsed.session, buf, { policy: { fingerprint: 'map' } });
    const fp = entities.find((e) => e.kind === 'fingerprint')!;
    expect(fp.action).toBe('map');
    expect(fp.canonicalText).toContain('AB:CD');
  });

  it('handles inconsistent offer/answer (missing session c=) with issues', () => {
    const offer = latin1(sdpBody([
      'v=0',
      'o=- 1 1 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 4000 RTP/AVP 0',
    ]));
    const answer = latin1(sdpBody([
      'v=0',
      'o=- 2 2 IN IP4 10.0.0.2',
      's=-',
      't=0 0',
      'm=audio 5000 RTP/AVP 0',
      'c=IN IP4 10.0.0.2',
    ]));

    const offerParsed = parseSdp(offer);
    const answerParsed = parseSdp(answer);
    expect(offerParsed.kind).toBe('complete');
    expect(answerParsed.kind).toBe('complete');

    if (offerParsed.kind !== 'complete' || answerParsed.kind !== 'complete') return;

    const offerEndpoints = buildSdpMediaEndpoints(offerParsed.session, offer);
    const answerEndpoints = buildSdpMediaEndpoints(answerParsed.session, answer);
    expect(offerEndpoints[0]!.port).toBe(4000);
    expect(answerEndpoints[0]!.port).toBe(5000);
    expect(offerEndpoints[0]!.address).toBe('10.0.0.1');
    expect(answerEndpoints[0]!.address).toBe('10.0.0.2');
  });
});
