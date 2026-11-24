import { describe, expect, it } from 'vitest';
import {
  decodeLatin1Span,
  decodeUtf8Span,
  parseSipMessage,
  sliceSpan,
  spansEqual,
  type ByteSpan,
} from '../../../src/pcap/protocols/application/sip';
import type { SipParseLimits } from '../../../src/pcap/protocols/application/sip';

function latin1(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function expectSpanText(buf: Uint8Array, span: ByteSpan, expected: string, utf8Mode = false): void {
  const slice = sliceSpan(buf, span);
  expect(Array.from(slice)).toEqual(Array.from(utf8Mode ? utf8(expected) : latin1(expected)));
  const decoded = utf8Mode ? decodeUtf8Span(buf, span) : decodeLatin1Span(buf, span);
  expect(decoded).toBe(expected);
}

describe('SIP byte-oriented message parser (step 2)', () => {
  it('parses a complete INVITE with CRLF and accurate spans', () => {
    const buf = latin1([
      'INVITE sip:alice@example.com:5060;transport=udp SIP/2.0\r\n',
      'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKabc\r\n',
      'From: <sip:alice@example.com>\r\n',
      'To: <sip:bob@example.com>\r\n',
      'Call-ID: abc@192.0.2.1\r\n',
      'Content-Length: 0\r\n',
      '\r\n',
    ].join(''));

    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;

    expect(result.consumed).toBe(buf.length);
    expectSpanText(buf, result.message.startLine.method, 'INVITE');
    expect(result.message.startLine.kind).toBe('request');
    expectSpanText(buf, result.message.startLine.requestUri.scheme, 'sip');
    expectSpanText(buf, result.message.startLine.requestUri.user!, 'alice');
    expectSpanText(buf, result.message.startLine.requestUri.host, 'example.com');
    expectSpanText(buf, result.message.startLine.requestUri.port!, '5060');
    expect(result.message.startLine.requestUri.parameters).toHaveLength(1);
    expectSpanText(buf, result.message.startLine.requestUri.parameters[0]!.name, 'transport');
    expectSpanText(buf, result.message.startLine.requestUri.parameters[0]!.value!, 'udp');

    const via = result.message.headers.find((h) => h.nameText.toLowerCase() === 'via')!;
    expectSpanText(buf, via.name, 'Via');
    expect(via.valueText).toContain('192.0.2.1');
    expect(result.message.body).toBeNull();
  });

  it('parses a SIP response with LF-only line endings', () => {
    const buf = latin1([
      'SIP/2.0 200 OK\n',
      'Call-ID: sess-1\n',
      'Content-Length: 4\n',
      '\n',
      'ping',
    ].join(''));

    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;

    expect(result.message.startLine.kind).toBe('response');
    expectSpanText(buf, result.message.startLine.statusCode, '200');
    expectSpanText(buf, result.message.startLine.reasonPhrase, 'OK');
    expect(result.message.body).not.toBeNull();
    expectSpanText(buf, result.message.body!.span, 'ping');
    expect(result.message.body!.contentType).toBeNull();
  });

  it('preserves UTF-8 byte spans in header values', () => {
    const display = 'Jakub Novák';
    const buf = concat(
      latin1('INVITE sip:a@b.c SIP/2.0\r\nFrom: "'),
      utf8(display),
      latin1('" <sip:a@b.c>\r\nContent-Length: 0\r\n\r\n'),
    );

    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;

    const from = result.message.headers.find((h) => h.nameText.toLowerCase() === 'from')!;
    expect(from.valueText).toContain(display);
    const quotedStart = buf.indexOf(0xc3); // start of UTF-8 Novák
    expect(from.value.offset <= quotedStart).toBe(true);
    expect(from.value.offset + from.value.length).toBeGreaterThan(quotedStart + display.length);
    expect(decodeUtf8Span(buf, from.value)).toContain(display);
  });

  it('accepts null bytes inside the body span', () => {
    const body = new Uint8Array([0x76, 0x00, 0x3d, 0x30]); // v\0=0
    const buf = concat(
      latin1('NOTIFY sip:a@b.c SIP/2.0\r\nContent-Length: 4\r\n\r\n'),
      body,
    );

    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;

    expect(result.message.body).not.toBeNull();
    expect(Array.from(sliceSpan(buf, result.message.body!.span))).toEqual(Array.from(body));
  });

  it('marks null byte in header name as malformed', () => {
    const buf = concat(
      latin1('INVITE sip:a@b.c SIP/2.0\r\nVia'),
      new Uint8Array([0x00]),
      latin1(': x\r\nContent-Length: 0\r\n\r\n'),
    );

    const result = parseSipMessage(buf);
    expect(result.kind).toBe('malformed');
    if (result.kind === 'malformed') {
      expect(result.reason).toBe('header-name-char');
    }
  });

  it('returns incomplete for truncated start line', () => {
    const buf = latin1('INVITE sip:alice@example.com SIP/2');
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('incomplete');
    if (result.kind === 'incomplete') {
      expect(result.reason).toBe('truncated-start-line');
    }
  });

  it('returns incomplete when Content-Length exceeds available body bytes', () => {
    const buf = latin1([
      'INVITE sip:a@b.c SIP/2.0\r\n',
      'Content-Length: 10\r\n',
      '\r\n',
      'short',
    ].join(''));

    const result = parseSipMessage(buf);
    expect(result.kind).toBe('incomplete');
    if (result.kind === 'incomplete') {
      expect(result.reason).toBe('truncated-body');
    }
  });

  it('returns incomplete when header/body separator is missing', () => {
    const buf = latin1('INVITE sip:a@b.c SIP/2.0\r\nCall-ID: x\r\n');
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('incomplete');
    if (result.kind === 'incomplete') {
      expect(result.reason).toBe('missing-header-body-separator');
    }
  });

  it('returns malformed when message exceeds maxMessageBytes', () => {
    const buf = latin1('INVITE sip:a@b.c SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const result = parseSipMessage(buf, {
      limits: {
        maxMessageBytes: buf.length - 1,
        maxHeaderCount: 256,
        maxLineBytes: 4_096,
        maxHeaderNameBytes: 256,
        maxUriBytes: 2_048,
        maxParameterCount: 64,
        maxParameterDepth: 8,
      },
    });
    expect(result.kind).toBe('malformed');
    if (result.kind === 'malformed') {
      expect(result.reason).toBe('message-too-large');
    }
  });

  it('returns incomplete for truncated header line', () => {
    const buf = latin1('INVITE sip:a@b.c SIP/2.0\r\nVia: SIP/2.0/UDP 1.2.3.4');
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('incomplete');
    if (result.kind === 'incomplete') {
      expect(result.reason).toBe('truncated-header-line');
    }
  });

  it('returns malformed when URI parameter count limit is exceeded', () => {
    const buf = latin1('INVITE sip:a@b.c;transport=udp;lr SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const result = parseSipMessage(buf, {
      limits: {
        maxMessageBytes: 65_536,
        maxHeaderCount: 256,
        maxLineBytes: 4_096,
        maxHeaderNameBytes: 256,
        maxUriBytes: 2_048,
        maxParameterCount: 1,
        maxParameterDepth: 8,
      },
    });
    expect(result.kind).toBe('malformed');
    if (result.kind === 'malformed') {
      expect(result.reason).toBe('parameter-count');
    }
  });

  it('returns malformed when maxParameterDepth disallows parameters', () => {
    const buf = latin1('INVITE sip:a@b.c;transport=udp SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const result = parseSipMessage(buf, {
      limits: {
        maxMessageBytes: 65_536,
        maxHeaderCount: 256,
        maxLineBytes: 4_096,
        maxHeaderNameBytes: 256,
        maxUriBytes: 2_048,
        maxParameterCount: 64,
        maxParameterDepth: 0,
      },
    });
    expect(result.kind).toBe('malformed');
    if (result.kind === 'malformed') {
      expect(result.reason).toBe('parameter-depth');
    }
  });

  it('returns malformed when header count limit is exceeded', () => {
    const lines = ['INVITE sip:a@b.c SIP/2.0'];
    for (let i = 0; i < 4; i++) lines.push(`X-H-${i}: v`);
    lines.push('Content-Length: 0', '', '');
    const buf = latin1(lines.join('\r\n') + '\r\n');

    const limits: SipParseLimits = {
      maxMessageBytes: 65_536,
      maxHeaderCount: 2,
      maxLineBytes: 4_096,
      maxHeaderNameBytes: 256,
      maxUriBytes: 2_048,
      maxParameterCount: 64,
      maxParameterDepth: 8,
    };

    const result = parseSipMessage(buf, { limits });
    expect(result.kind).toBe('malformed');
    if (result.kind === 'malformed') {
      expect(result.reason).toBe('header-count-limit');
    }
  });

  it('returns malformed when a line exceeds maxLineBytes', () => {
    const longValue = 'x'.repeat(20);
    const buf = latin1(`INVITE sip:a@b.c SIP/2.0\r\nX-L: ${longValue}\r\nContent-Length: 0\r\n\r\n`);
    const limits: SipParseLimits = {
      maxMessageBytes: 65_536,
      maxHeaderCount: 256,
      maxLineBytes: 10,
      maxHeaderNameBytes: 256,
      maxUriBytes: 2_048,
      maxParameterCount: 64,
      maxParameterDepth: 8,
    };
    const result = parseSipMessage(buf, { limits });
    expect(result.kind).toBe('malformed');
  });

  it('returns not-sip for non-SIP binary payload', () => {
    const buf = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xff]);
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('not-sip');
  });

  it('accepts unknown methods with otherwise valid SIP structure', () => {
    const buf = latin1('FOO sip:a@b.c SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
    if (result.kind === 'complete') {
      expectSpanText(buf, result.message.startLine.method, 'FOO');
    }
  });

  it('parses angle-bracketed Request-URI on the start line', () => {
    const buf = latin1('INVITE <sip:user@host.example> SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;
    expectSpanText(buf, result.message.startLine.requestUri.user!, 'user');
    expectSpanText(buf, result.message.startLine.requestUri.host, 'host.example');
  });

  it('never throws on corrupted input', () => {
    const samples = [
      new Uint8Array(0),
      new Uint8Array(100).fill(0xff),
      latin1('INVITE\r\n'),
      latin1('SIP/2.0 999\r\n'),
    ];
    for (const buf of samples) {
      expect(() => parseSipMessage(buf)).not.toThrow();
    }
  });

  it('span helpers compare equal spans', () => {
    expect(spansEqual({ offset: 3, length: 5 }, { offset: 3, length: 5 })).toBe(true);
    expect(spansEqual({ offset: 3, length: 5 }, { offset: 3, length: 4 })).toBe(false);
  });
});

describe('SIP flag parameters (RFC 3261 generic-param without "=")', () => {
  it('accepts a flag parameter on the Request-URI (route ;lr)', () => {
    const buf = latin1('INVITE sip:proxy.example.com;lr SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;
    const params = result.message.startLine.requestUri.parameters;
    expect(params).toHaveLength(1);
    expectSpanText(buf, params[0]!.name, 'lr');
    expect(params[0]!.value).toBeNull();
  });

  it('accepts a flag parameter on a Contact URI (;ob)', () => {
    const buf = latin1([
      'MESSAGE sip:RADIO2@10.230.0.20:5060 SIP/2.0\r\n',
      'Contact: "DISP UNIT15" <sip:DISPUNIT15@10.230.0.10:5060;ob>\r\n',
      'Content-Length: 0\r\n',
      '\r\n',
    ].join(''));
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;
    const contact = result.message.headers.find((h) => h.nameText.toLowerCase() === 'contact')!;
    expect(contact).toBeDefined();
  });

  it('accepts a flag parameter mixed with a value parameter on a header (Via ;rport;branch=)', () => {
    const buf = latin1([
      'INVITE sip:a@b.c SIP/2.0\r\n',
      'Via: SIP/2.0/UDP 192.0.2.1:5060;rport;branch=z9hG4bKabc\r\n',
      'Content-Length: 0\r\n',
      '\r\n',
    ].join(''));
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;
    const via = result.message.headers.find((h) => h.nameText.toLowerCase() === 'via')!;
    expect(via.parameters).toHaveLength(2);
    expectSpanText(buf, via.parameters[0]!.name, 'rport');
    expect(via.parameters[0]!.value).toBeNull();
    expectSpanText(buf, via.parameters[1]!.name, 'branch');
    expectSpanText(buf, via.parameters[1]!.value!, 'z9hG4bKabc');
  });

  it('accepts a value parameter followed by a flag parameter (order-independent)', () => {
    const buf = latin1('INVITE sip:a@b.c;transport=tcp;lr SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;
    const params = result.message.startLine.requestUri.parameters;
    expect(params).toHaveLength(2);
    expectSpanText(buf, params[0]!.name, 'transport');
    expectSpanText(buf, params[0]!.value!, 'tcp');
    expectSpanText(buf, params[1]!.name, 'lr');
    expect(params[1]!.value).toBeNull();
  });

  it('accepts a bare flag parameter with LF-only line endings', () => {
    const buf = latin1('INVITE sip:a@b.c;lr SIP/2.0\nContent-Length: 0\n\n');
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;
    const params = result.message.startLine.requestUri.parameters;
    expect(params).toHaveLength(1);
    expectSpanText(buf, params[0]!.name, 'lr');
    expect(params[0]!.value).toBeNull();
  });

  it('still rejects an empty parameter name (";=value")', () => {
    const buf = latin1('INVITE sip:a@b.c;=value SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('malformed');
    if (result.kind === 'malformed') {
      expect(result.reason).toBe('parameter-name');
    }
  });

  it('still rejects an empty parameter value after an explicit "=" (";name=")', () => {
    const buf = latin1('INVITE sip:a@b.c;transport= SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('malformed');
    if (result.kind === 'malformed') {
      expect(result.reason).toBe('parameter-value');
    }
  });

  it('still rejects a disallowed character in a parameter name', () => {
    const buf = latin1('INVITE sip:a@b.c;l,r=x SIP/2.0\r\nContent-Length: 0\r\n\r\n');
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('malformed');
    if (result.kind === 'malformed') {
      expect(result.reason).toBe('parameter-name');
    }
  });

  it('parses the real-world MESSAGE payload with ;ob without misclassifying it as malformed', () => {
    const buf = latin1([
      'MESSAGE sip:RADIO2@10.230.0.20:5060 SIP/2.0\r\n',
      'Via: SIP/2.0/UDP 10.230.0.10:5060;branch=z9hG4bKabcdef\r\n',
      'From: "DISP UNIT15" <sip:DISPUNIT15@10.230.0.10>;tag=c91\r\n',
      'To: <sip:RADIO2@10.230.0.20>\r\n',
      'Call-ID: ef9b632f-23b0-46d1-8c62-a4cf4ec76dfa\r\n',
      'CSeq: 48911 MESSAGE\r\n',
      'Contact: "DISP UNIT15" <sip:DISPUNIT15@10.230.0.10:5060;ob>\r\n',
      'User-Agent: EXAMPLE-AGENT-1.0.0\r\n',
      'Content-Length: 0\r\n',
      '\r\n',
    ].join(''));
    const result = parseSipMessage(buf);
    expect(result.kind).toBe('complete');
  });
});
