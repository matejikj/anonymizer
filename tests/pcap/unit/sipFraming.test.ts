import { describe, expect, it } from 'vitest';
import {
  canonicalizeHeaderName,
  classifySipPayload,
  headerNameEquals,
  isSipPortHint,
  parseSipMessage,
  parseSipMessages,
} from '../../../src/pcap/protocols/application/sip';

function latin1(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

describe('SIP framing and header parser (step 3)', () => {
  describe('compact header names', () => {
    it('expands RFC 3261 compact forms to canonical names', () => {
      expect(canonicalizeHeaderName('v')).toBe('via');
      expect(canonicalizeHeaderName('f')).toBe('from');
      expect(canonicalizeHeaderName('t')).toBe('to');
      expect(canonicalizeHeaderName('i')).toBe('call-id');
      expect(canonicalizeHeaderName('m')).toBe('contact');
      expect(canonicalizeHeaderName('l')).toBe('content-length');
      expect(canonicalizeHeaderName('c')).toBe('content-type');
    });

    it('parses a message using compact header names', () => {
      const buf = latin1([
        'INVITE sip:a@b.c SIP/2.0\r\n',
        'v: SIP/2.0/UDP 10.0.0.1:5060\r\n',
        'f: <sip:a@b.c>\r\n',
        't: <sip:b@b.c>\r\n',
        'i: sess-1@10.0.0.1\r\n',
        'l: 0\r\n',
        '\r\n',
      ].join(''));

      const result = parseSipMessage(buf);
      expect(result.kind).toBe('complete');
      if (result.kind !== 'complete') return;

      const via = result.message.headers.find((h) => h.canonicalNameText === 'via')!;
      expect(via.nameText).toBe('v');
      expect(headerNameEquals(via, 'Via')).toBe(true);
      expect(result.message.headers.some((h) => h.canonicalNameText === 'call-id')).toBe(true);
    });

    it('treats header names case-insensitively', () => {
      const buf = latin1('INVITE sip:a@b.c SIP/2.0\r\nVIA: x\r\nvia: y\r\nContent-Length: 0\r\n\r\n');
      const result = parseSipMessage(buf);
      expect(result.kind).toBe('complete');
      if (result.kind !== 'complete') return;
      const vias = result.message.headers.filter((h) => h.canonicalNameText === 'via');
      expect(vias).toHaveLength(2);
      expect(vias[0]!.nameText).toBe('VIA');
      expect(vias[1]!.nameText).toBe('via');
    });
  });

  describe('folded headers', () => {
    it('unfolds a folded Via header into one logical value', () => {
      const buf = latin1([
        'INVITE sip:a@b.c SIP/2.0\r\n',
        'Via: SIP/2.0/UDP 10.0.0.1:5060;\r\n',
        ' branch=z9hG4bKabc\r\n',
        'Content-Length: 0\r\n',
        '\r\n',
      ].join(''));

      const result = parseSipMessage(buf);
      expect(result.kind).toBe('complete');
      if (result.kind !== 'complete') return;

      const viaHeaders = result.message.headers.filter((h) => h.canonicalNameText === 'via');
      expect(viaHeaders).toHaveLength(1);
      expect(viaHeaders[0]!.valueText).toContain('branch=z9hG4bKabc');
      expect(viaHeaders[0]!.valueText).not.toContain('\r\n');
    });

    it('supports multiple folded continuation lines', () => {
      const buf = latin1([
        'INVITE sip:a@b.c SIP/2.0\r\n',
        'Subject: Long\r\n',
        ' subject\r\n',
        ' continuation\r\n',
        'Content-Length: 0\r\n',
        '\r\n',
      ].join(''));

      const result = parseSipMessage(buf);
      expect(result.kind).toBe('complete');
      if (result.kind !== 'complete') return;

      const subject = result.message.headers.find((h) => h.canonicalNameText === 'subject')!;
      expect(subject.valueText).toBe('Long subject continuation');
    });
  });

  describe('repeated and comma-separated headers', () => {
    it('keeps repeated Via headers as separate entries', () => {
      const buf = latin1([
        'INVITE sip:a@b.c SIP/2.0\r\n',
        'Via: SIP/2.0/UDP 1.1.1.1:5060\r\n',
        'Via: SIP/2.0/UDP 2.2.2.2:5060\r\n',
        'Content-Length: 0\r\n',
        '\r\n',
      ].join(''));

      const result = parseSipMessage(buf);
      expect(result.kind).toBe('complete');
      if (result.kind !== 'complete') return;

      const vias = result.message.headers.filter((h) => h.canonicalNameText === 'via');
      expect(vias).toHaveLength(2);
    });

    it('preserves comma-separated values in a single header line', () => {
      const buf = latin1([
        'INVITE sip:a@b.c SIP/2.0\r\n',
        'Accept: application/sdp, application/pkcs7-mime\r\n',
        'Content-Length: 0\r\n',
        '\r\n',
      ].join(''));

      const result = parseSipMessage(buf);
      expect(result.kind).toBe('complete');
      if (result.kind !== 'complete') return;

      const accept = result.message.headers.find((h) => h.canonicalNameText === 'accept')!;
      expect(accept.valueText).toBe('application/sdp, application/pkcs7-mime');
    });
  });

  describe('Content-Length framing', () => {
    it('accepts leading zeros in Content-Length', () => {
      const buf = latin1([
        'INVITE sip:a@b.c SIP/2.0\r\n',
        'Content-Length: 004\r\n',
        '\r\n',
        'body',
      ].join(''));

      const result = parseSipMessage(buf);
      expect(result.kind).toBe('complete');
      if (result.kind !== 'complete') return;
      expect(result.consumed).toBe(buf.length);
    });

    it('uses compact l: for Content-Length framing', () => {
      const buf = latin1([
        'NOTIFY sip:a@b.c SIP/2.0\r\n',
        'l: 3\r\n',
        '\r\n',
        'abc',
      ].join(''));

      const result = parseSipMessage(buf);
      expect(result.kind).toBe('complete');
      if (result.kind !== 'complete') return;
      expect(result.message.body!.span.length).toBe(3);
    });

    it('returns malformed for non-numeric Content-Length', () => {
      const buf = latin1('INVITE sip:a@b.c SIP/2.0\r\nContent-Length: abc\r\n\r\n');
      const result = parseSipMessage(buf);
      expect(result.kind).toBe('malformed');
      if (result.kind === 'malformed') {
        expect(result.reason).toBe('invalid-content-length');
      }
    });

    it('returns malformed for empty Content-Length value', () => {
      const buf = latin1('INVITE sip:a@b.c SIP/2.0\r\nContent-Length: \r\n\r\n');
      const result = parseSipMessage(buf);
      expect(result.kind).toBe('malformed');
      if (result.kind === 'malformed') {
        expect(result.reason).toBe('invalid-content-length');
      }
    });

    it('returns malformed for conflicting Content-Length headers', () => {
      const buf = latin1([
        'INVITE sip:a@b.c SIP/2.0\r\n',
        'Content-Length: 0\r\n',
        'Content-Length: 5\r\n',
        '\r\n',
      ].join(''));

      const result = parseSipMessage(buf);
      expect(result.kind).toBe('malformed');
      if (result.kind === 'malformed') {
        expect(result.reason).toBe('conflicting-content-length');
      }
    });

    it('accepts duplicate Content-Length when values agree', () => {
      const buf = latin1([
        'INVITE sip:a@b.c SIP/2.0\r\n',
        'Content-Length: 2\r\n',
        'Content-Length: 2\r\n',
        '\r\n',
        'ok',
      ].join(''));

      const result = parseSipMessage(buf);
      expect(result.kind).toBe('complete');
      if (result.kind !== 'complete') return;
      expect(result.message.body!.span.length).toBe(2);
    });
  });

  describe('TCP multi-message framing', () => {
    it('parses two complete messages in one buffer', () => {
      const msg1 = [
        'INVITE sip:a@b.c SIP/2.0\r\n',
        'Call-ID: 1\r\n',
        'Content-Length: 0\r\n',
        '\r\n',
      ].join('');
      const msg2 = [
        'SIP/2.0 200 OK\r\n',
        'Call-ID: 1\r\n',
        'Content-Length: 0\r\n',
        '\r\n',
      ].join('');
      const buf = latin1(msg1 + msg2);

      const stream = parseSipMessages(buf);
      expect(stream.messages).toHaveLength(2);
      expect(stream.tail).toBeNull();
      expect(stream.totalConsumed).toBe(buf.length);
      expect(stream.messages[0]!.message.startLine.kind).toBe('request');
      expect(stream.messages[1]!.message.startLine.kind).toBe('response');
    });

    it('stops at an incomplete tail after complete messages', () => {
      const complete = latin1('INVITE sip:a@b.c SIP/2.0\r\nContent-Length: 0\r\n\r\n');
      const partial = latin1('SIP/2.0 200 OK\r\nCall-ID: x\r\n');
      const buf = new Uint8Array(complete.length + partial.length);
      buf.set(complete, 0);
      buf.set(partial, complete.length);

      const stream = parseSipMessages(buf);
      expect(stream.messages).toHaveLength(1);
      expect(stream.tail?.kind).toBe('incomplete');
    });

    it('leaves extra bytes after a framed message for the next parse', () => {
      const msg = latin1('INVITE sip:a@b.c SIP/2.0\r\nContent-Length: 0\r\n\r\n');
      const extra = latin1('NOT SIP');
      const buf = new Uint8Array(msg.length + extra.length);
      buf.set(msg, 0);
      buf.set(extra, msg.length);

      const first = parseSipMessage(buf);
      expect(first.kind).toBe('complete');
      if (first.kind !== 'complete') return;
      expect(first.consumed).toBe(msg.length);

      const second = parseSipMessage(buf, { offset: first.consumed, length: buf.length - first.consumed });
      expect(second.kind).toBe('not-sip');
    });
  });

  describe('SIP payload classification', () => {
    it('recognizes port 5060 and 5061 as hints', () => {
      expect(isSipPortHint(5060, 1234)).toBe(true);
      expect(isSipPortHint(1234, 5061)).toBe(true);
      expect(isSipPortHint(8080, 9090)).toBe(false);
    });

    it('accepts valid SIP on a non-hint port only after complete parse', () => {
      const buf = latin1('INVITE sip:a@b.c SIP/2.0\r\nContent-Length: 0\r\n\r\n');
      const complete = classifySipPayload(buf, 0, buf.length, { portHint: false });
      expect(complete.kind).toBe('complete');

      const truncated = latin1('INVITE sip:a@b.c SIP/2.0\r\nContent-Length: 10\r\n\r\nshort');
      const incomplete = classifySipPayload(truncated, 0, truncated.length, { portHint: false });
      expect(incomplete.kind).toBe('not-sip');
      if (incomplete.kind === 'not-sip') {
        expect(incomplete.reason).toBe('content-validation-failed');
      }
    });

    it('surfaces incomplete SIP on hint ports', () => {
      const buf = latin1('INVITE sip:a@b.c SIP/2.0\r\nContent-Length: 10\r\n\r\nshort');
      const result = classifySipPayload(buf, 0, buf.length, { portHint: true });
      expect(result.kind).toBe('incomplete');
      if (result.kind === 'incomplete') {
        expect(result.reason).toBe('truncated-body');
      }
    });

    it('does not treat HTTP-like text as SIP without valid structure', () => {
      const buf = latin1('GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n');
      const result = classifySipPayload(buf, 0, buf.length, { portHint: true });
      expect(result.kind).toBe('not-sip');
    });

    it('treats unknown methods with valid SIP structure as SIP', () => {
      const buf = latin1('CUSTOM sip:a@b.c SIP/2.0\r\nContent-Length: 0\r\n\r\n');
      const result = classifySipPayload(buf, 0, buf.length, { portHint: false });
      expect(result.kind).toBe('complete');
    });
  });
});
