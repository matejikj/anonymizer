/**
 * Parse SIP header value parts: name-addrs, Via sent-by, Digest parameters.
 */

import type { SipParseLimits } from './limits';
import type { ByteSpan } from './types';
import { decodeLatin1Span, decodeUtf8Span, findByte, isSpaceByte, skipSpaces, spanOf } from './bytes';
import { parseSipUri } from './uri';

export interface ParsedDisplayName {
  readonly span: ByteSpan;
  readonly text: string;
}

export interface ParsedNameAddr {
  readonly displayName: ParsedDisplayName | null;
  readonly uriSpan: ByteSpan;
}

/** Split comma-separated header values respecting quotes and angle brackets. */
export function splitCommaSeparatedSpans(
  buffer: Uint8Array,
  start: number,
  end: number,
): readonly ByteSpan[] {
  const parts: ByteSpan[] = [];
  let partStart = start;
  let i = start;
  let inQuote = false;
  let angleDepth = 0;

  while (i < end) {
    const b = buffer[i]!;
    if (b === 0x22 && (i === start || buffer[i - 1] !== 0x5c)) {
      inQuote = !inQuote;
    } else if (!inQuote) {
      if (b === 0x3c) angleDepth++;
      else if (b === 0x3e && angleDepth > 0) angleDepth--;
      else if (b === 0x2c && angleDepth === 0) {
        const trimmed = trimSpanBounds(buffer, partStart, i);
        if (trimmed.length > 0) parts.push(trimmed);
        partStart = i + 1;
      }
    }
    i++;
  }

  const trimmed = trimSpanBounds(buffer, partStart, end);
  if (trimmed.length > 0) parts.push(trimmed);
  return parts;
}

function trimSpanBounds(buffer: Uint8Array, start: number, end: number): ByteSpan {
  let s = skipSpaces(buffer, start, end);
  let e = end;
  while (e > s && (buffer[e - 1] === 0x20 || buffer[e - 1] === 0x09)) e--;
  return spanOf(s, e);
}

/** Parse `"Display Name" <uri>`, `Display Name <uri>`, or bare URI/name-addr from a value slice. */
export function parseNameAddr(
  buffer: Uint8Array,
  start: number,
  end: number,
): ParsedNameAddr | null {
  const trimmed = trimSpanBounds(buffer, start, end);
  if (trimmed.length === 0) return null;

  let cursor = trimmed.offset;
  const limit = trimmed.offset + trimmed.length;
  let displayName: ParsedDisplayName | null = null;

  if (buffer[cursor] === 0x22) {
    const quoteEnd = findUnescapedQuote(buffer, cursor + 1, limit);
    if (quoteEnd < 0) return null;
    displayName = {
      span: spanOf(cursor + 1, quoteEnd),
      text: decodeUtf8Span(buffer, spanOf(cursor + 1, quoteEnd)),
    };
    cursor = quoteEnd + 1;
    cursor = skipSpaces(buffer, cursor, limit);
  } else {
    const lt = findByte(buffer, cursor, limit, 0x3c);
    if (lt >= 0 && lt > cursor) {
      const namePart = trimSpanBounds(buffer, cursor, lt);
      if (namePart.length > 0) {
        displayName = {
          span: namePart,
          text: decodeUtf8Span(buffer, namePart),
        };
      }
      cursor = lt;
    }
  }

  let uriStart = cursor;
  let uriEnd = limit;
  if (buffer[cursor] === 0x3c) {
    uriStart = cursor + 1;
    const close = findByte(buffer, uriStart, limit, 0x3e);
    if (close < 0) return null;
    uriEnd = close;
    cursor = close + 1;
  } else {
    const semi = findByte(buffer, uriStart, uriEnd, 0x3b);
    if (semi >= 0) uriEnd = semi;
  }

  if (uriEnd <= uriStart) return null;
  return {
    displayName,
    uriSpan: spanOf(uriStart, uriEnd),
  };
}

function findUnescapedQuote(buffer: Uint8Array, start: number, end: number): number {
  for (let i = start; i < end; i++) {
    if (buffer[i] === 0x22 && buffer[i - 1] !== 0x5c) return i;
  }
  return -1;
}

/** Parse `SIP/2.0/UDP host:port;params` sent-by portion. */
export interface ParsedViaSentBy {
  readonly hostSpan: ByteSpan;
  readonly portSpan: ByteSpan | null;
  readonly paramStart: number;
  readonly paramEnd: number;
}

export function parseViaSentBy(
  buffer: Uint8Array,
  start: number,
  end: number,
): ParsedViaSentBy | null {
  const trimmed = trimSpanBounds(buffer, start, end);
  if (trimmed.length === 0) return null;

  let cursor = trimmed.offset;
  const limit = trimmed.offset + trimmed.length;

  const slash1 = findByte(buffer, cursor, limit, 0x2f);
  if (slash1 < 0) return null;
  const slash2 = findByte(buffer, slash1 + 1, limit, 0x2f);
  if (slash2 < 0) return null;
  cursor = slash2 + 1;
  while (cursor < limit && !isSpaceByte(buffer[cursor]!)) cursor++;
  cursor = skipSpaces(buffer, cursor, limit);

  const semi = findByte(buffer, cursor, limit, 0x3b);
  const sentEnd = semi >= 0 ? semi : limit;
  const sentStart = cursor;

  let hostStart = sentStart;
  let hostEnd = sentEnd;
  let portSpan: ByteSpan | null = null;

  if (buffer[sentStart] === 0x5b) {
    const close = findByte(buffer, sentStart + 1, sentEnd, 0x5d);
    if (close < 0) return null;
    hostStart = sentStart + 1;
    hostEnd = close;
    const colon = findByte(buffer, close + 1, sentEnd, 0x3a);
    if (colon >= 0 && colon + 1 < sentEnd) {
      portSpan = spanOf(colon + 1, sentEnd);
    }
  } else {
    const colon = findByte(buffer, sentStart, sentEnd, 0x3a);
    if (colon >= 0) {
      hostEnd = colon;
      portSpan = spanOf(colon + 1, sentEnd);
    }
  }

  if (hostEnd <= hostStart) return null;

  return {
    hostSpan: spanOf(hostStart, hostEnd),
    portSpan,
    paramStart: semi >= 0 ? semi + 1 : limit,
    paramEnd: limit,
  };
}

export interface ParsedAuthParam {
  readonly nameSpan: ByteSpan;
  readonly nameText: string;
  readonly valueSpan: ByteSpan;
  readonly valueText: string;
}

export interface ParsedAuthParams {
  readonly params: readonly ParsedAuthParam[];
  /** True when every byte of the credential value after the scheme was parsed. */
  readonly complete: boolean;
  /** First unparsed byte offset when complete is false. */
  readonly tailOffset: number;
}

/** Parse Digest `key="value"` / `key=value` pairs in credential headers. */
export function parseAuthParams(
  buffer: Uint8Array,
  start: number,
  end: number,
): ParsedAuthParams {
  const params: ParsedAuthParam[] = [];
  let cursor = start;

  if (cursor < end) {
    const digestEnd = Math.min(end, cursor + 6);
    if (decodeLatin1Span(buffer, spanOf(cursor, digestEnd)).toLowerCase() === 'digest') {
      cursor = skipSpaces(buffer, digestEnd, end);
      if (cursor < end && buffer[cursor] === 0x20) cursor++;
    }
  }

  while (cursor < end) {
    cursor = skipSpaces(buffer, cursor, end);
    if (cursor >= end) break;

    const eq = findByte(buffer, cursor, end, 0x3d);
    if (eq <= cursor) break;

    const nameSpan = spanOf(cursor, eq);
    const nameText = decodeLatin1Span(buffer, nameSpan).toLowerCase();
    let valueStart = eq + 1;
    let valueEnd = end;

    if (valueStart < end && buffer[valueStart] === 0x22) {
      valueStart++;
      const quoteEnd = findUnescapedQuote(buffer, valueStart, end);
      if (quoteEnd < 0) break;
      valueEnd = quoteEnd;
      cursor = quoteEnd + 1;
    } else {
      const comma = findByte(buffer, valueStart, end, 0x2c);
      valueEnd = comma >= 0 ? comma : end;
      cursor = valueEnd;
    }

    params.push({
      nameSpan,
      nameText,
      valueSpan: spanOf(valueStart, valueEnd),
      valueText: decodeUtf8Span(buffer, spanOf(valueStart, valueEnd)),
    });

    cursor = skipSpaces(buffer, cursor, end);
    if (cursor < end && buffer[cursor] === 0x2c) cursor++;
  }

  cursor = skipSpaces(buffer, cursor, end);
  return {
    params,
    complete: cursor >= end,
    tailOffset: cursor,
  };
}

export function parseUriInSpan(
  buffer: Uint8Array,
  span: ByteSpan,
  limits: SipParseLimits,
) {
  return parseSipUri(buffer, span.offset, span.offset + span.length, limits);
}
