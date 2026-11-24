/**
 * M-2 — non-identifying SDP attributes/lines must survive anonymization instead of being
 * blanket-redacted: rtpmap/fmtp/X-nat (codec/negotiation attributes) and b=/t= (bandwidth,
 * timing — numeric-only by the SDP grammar). s=/i=/u=/e=/p=/k= stay redacted: unlike b=/t=,
 * they are arbitrary free text (or a literal key) that can legitimately carry something
 * sensitive, per real-world evidence (see headerPolicy.ts's User-Agent finding for the
 * same class of mistake in the other direction).
 */

import { describe, expect, it } from 'vitest';
import { extractSdpEntities, parseSdp } from '../../../src/pcap/protocols/application/sdp';

function latin1(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

function sdpBody(lines: string[]): string {
  return `${lines.join('\r\n')}\r\n`;
}

describe('M-2 SDP preserved fields', () => {
  it('preserves rtpmap/fmtp/X-nat attributes (no entity, no redaction)', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=- 1 2 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 5004 RTP/AVP 8 120',
      'a=rtpmap:8 PCMA/8000',
      'a=rtpmap:120 telephone-event/8000',
      'a=fmtp:120 0-16',
      'a=X-nat:0',
    ]));
    const parsed = parseSdp(buf);
    expect(parsed.kind).toBe('complete');
    if (parsed.kind !== 'complete') return;
    const { entities } = extractSdpEntities(parsed.session, buf);
    expect(entities.some((e) => e.field.includes('rtpmap'))).toBe(false);
    expect(entities.some((e) => e.field.includes('fmtp'))).toBe(false);
    expect(entities.some((e) => e.field.includes('x-nat') || e.field.includes('X-nat'))).toBe(false);
    expect(entities.some((e) => e.kind === 'unknown-attribute')).toBe(false);
  });

  it('preserves b= and t= lines but keeps s=/k= redacted', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=- 1 2 IN IP4 10.0.0.1',
      's=A Real Meeting Title',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'b=AS:84',
      'k=clear:SuperSecretKey',
      'm=audio 5004 RTP/AVP 0',
    ]));
    const parsed = parseSdp(buf);
    expect(parsed.kind).toBe('complete');
    if (parsed.kind !== 'complete') return;
    const { entities } = extractSdpEntities(parsed.session, buf);
    expect(entities.some((e) => e.field === 'b.value')).toBe(false);
    expect(entities.some((e) => e.field === 't.value')).toBe(false);
    expect(entities.some((e) => e.field === 's.value' && e.action === 'redact')).toBe(true);
    expect(entities.some((e) => e.field === 'k.value' && e.action === 'redact')).toBe(true);
  });

  it('still redacts genuinely unknown/vendor attributes', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=- 1 2 IN IP4 10.0.0.1',
      's=-',
      'c=IN IP4 10.0.0.1',
      't=0 0',
      'm=audio 5004 RTP/AVP 0',
      'a=x-secret-token:abc123',
    ]));
    const parsed = parseSdp(buf);
    expect(parsed.kind).toBe('complete');
    if (parsed.kind !== 'complete') return;
    const { entities } = extractSdpEntities(parsed.session, buf);
    expect(entities.some((e) => e.kind === 'unknown-attribute' && e.action === 'redact')).toBe(true);
  });
});
