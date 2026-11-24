/**
 * SIP start-line parser (request and response).
 */

import type { SipParseLimits } from './limits';
import type { SipStartLine } from './types';
import {
  bytesEqualAsciiIgnoreCase,
  decodeLatin1Span,
  findByte,
  isMethodChar,
  skipSpaces,
  spanOf,
} from './bytes';
import { parseSipUri } from './uri';

export type StartLineParseResult =
  | { readonly ok: true; readonly startLine: SipStartLine; readonly nextOffset: number }
  | { readonly ok: false; readonly reason: string; readonly kind: 'not-sip' | 'malformed' | 'incomplete' };

export function parseStartLine(
  buffer: Uint8Array,
  start: number,
  _end: number,
  lineBreak: number,
  limits: SipParseLimits,
): StartLineParseResult {
  const lineLength = lineBreak - start;
  if (lineLength <= 0) return { ok: false, reason: 'empty-start-line', kind: 'malformed' };
  if (lineLength > limits.maxLineBytes) return { ok: false, reason: 'start-line-too-long', kind: 'malformed' };

  if (bytesEqualAsciiIgnoreCase(buffer, start, Math.min(start + 4, lineBreak), 'SIP/')) {
    return parseResponseStartLine(buffer, start, lineBreak);
  }
  return parseRequestStartLine(buffer, start, lineBreak, limits);
}

function parseRequestStartLine(
  buffer: Uint8Array,
  start: number,
  lineBreak: number,
  limits: SipParseLimits,
): StartLineParseResult {
  const methodEnd = findByte(buffer, start, lineBreak, 0x20);
  if (methodEnd <= start) return { ok: false, reason: 'missing-method', kind: 'malformed' };
  for (let i = start; i < methodEnd; i++) {
    if (!isMethodChar(buffer[i]!)) return { ok: false, reason: 'invalid-method', kind: 'malformed' };
  }

  let versionStart = -1;
  for (let i = Math.max(start, lineBreak - 7); i >= start; i--) {
    if (i + 7 <= lineBreak && bytesEqualAsciiIgnoreCase(buffer, i, i + 7, 'SIP/2.0')) {
      versionStart = i;
      break;
    }
  }
  if (versionStart < 0) return { ok: false, reason: 'missing-version', kind: 'malformed' };

  let uriStart = skipSpaces(buffer, methodEnd + 1, versionStart);
  let uriEnd = versionStart;
  while (uriEnd > uriStart && buffer[uriEnd - 1] === 0x20) uriEnd--;

  if (buffer[uriStart] === 0x3c) {
    uriStart++;
    if (uriEnd > uriStart && buffer[uriEnd - 1] === 0x3e) uriEnd--;
  }

  if (uriEnd <= uriStart) return { ok: false, reason: 'missing-request-uri', kind: 'malformed' };

  const uri = parseSipUri(buffer, uriStart, uriEnd, limits);
  if (!uri.ok) return { ok: false, reason: uri.reason, kind: 'malformed' };

  const methodSpan = spanOf(start, methodEnd);
  return {
    ok: true,
    startLine: {
      kind: 'request',
      span: spanOf(start, lineBreak),
      method: methodSpan,
      methodText: decodeLatin1Span(buffer, methodSpan),
      requestUri: uri.uri,
      version: spanOf(versionStart, versionStart + 7),
    },
    nextOffset: lineBreak,
  };
}

function parseResponseStartLine(
  buffer: Uint8Array,
  start: number,
  lineBreak: number,
): StartLineParseResult {
  const versionEnd = findByte(buffer, start, lineBreak, 0x20);
  if (versionEnd <= start) return { ok: false, reason: 'missing-version', kind: 'malformed' };
  if (!bytesEqualAsciiIgnoreCase(buffer, start, versionEnd, 'SIP/2.0')) {
    return { ok: false, reason: 'invalid-version', kind: 'malformed' };
  }

  let cursor = skipSpaces(buffer, versionEnd + 1, lineBreak);
  const codeStart = cursor;
  if (codeStart >= lineBreak) return { ok: false, reason: 'missing-status-code', kind: 'malformed' };

  let codeEnd = codeStart;
  while (codeEnd < lineBreak && buffer[codeEnd]! >= 0x30 && buffer[codeEnd]! <= 0x39) codeEnd++;
  if (codeEnd - codeStart !== 3) return { ok: false, reason: 'invalid-status-code', kind: 'malformed' };

  cursor = skipSpaces(buffer, codeEnd, lineBreak);
  const statusSpan = spanOf(codeStart, codeEnd);
  return {
    ok: true,
    startLine: {
      kind: 'response',
      span: spanOf(start, lineBreak),
      version: spanOf(start, versionEnd),
      statusCode: statusSpan,
      statusCodeText: decodeLatin1Span(buffer, statusSpan),
      reasonPhrase: spanOf(cursor, lineBreak),
    },
    nextOffset: lineBreak,
  };
}

/** Quick probe: could this buffer plausibly start a SIP message? */
export function looksLikeSipStart(buffer: Uint8Array, start: number, end: number): boolean {
  if (start >= end) return false;
  if (bytesEqualAsciiIgnoreCase(buffer, start, Math.min(start + 4, end), 'SIP/')) return true;

  const space = findByte(buffer, start, end, 0x20);
  if (space <= start || space - start > 64) return false;
  for (let i = start; i < space; i++) {
    if (!isMethodChar(buffer[i]!)) return false;
  }
  let afterMethod = skipSpaces(buffer, space + 1, end);
  if (afterMethod >= end) return false;
  if (buffer[afterMethod] === 0x3c) {
    afterMethod++;
  }
  const colon = findByte(buffer, afterMethod, end, 0x3a);
  if (colon <= afterMethod) return false;
  const schemeLen = colon - afterMethod;
  if (schemeLen < 3 || schemeLen > 5) return false;
  const scheme = decodeLatin1Span(buffer, spanOf(afterMethod, colon)).toLowerCase();
  return scheme === 'sip' || scheme === 'sips' || scheme === 'tel';
}
