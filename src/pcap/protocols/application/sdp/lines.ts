/**
 * Low-level SDP line token helpers with byte spans.
 */

import type { ByteSpan } from '../sip/types';
import { decodeLatin1Span, findLineBreak, isEmptyLine, lineTerminatorLength, skipSpaces, spanOf } from '../sip/bytes';

export { decodeLatin1Span, findLineBreak, lineTerminatorLength, spanOf };

export function splitSpannedTokens(
  buffer: Uint8Array,
  start: number,
  end: number,
  maxTokens: number,
): readonly ByteSpan[] {
  const tokens: ByteSpan[] = [];
  let cursor = skipSpaces(buffer, start, end);

  while (cursor < end && tokens.length < maxTokens) {
    const tokenStart = cursor;
    while (cursor < end && buffer[cursor] !== 0x20 && buffer[cursor] !== 0x09) cursor++;
    if (cursor > tokenStart) tokens.push(spanOf(tokenStart, cursor));
    cursor = skipSpaces(buffer, cursor, end);
  }

  return tokens;
}

export function parseTypedLine(
  buffer: Uint8Array,
  lineStart: number,
  lineBreak: number,
): { readonly ok: true; readonly type: string; readonly valueStart: number; readonly valueEnd: number }
  | { readonly ok: false; readonly reason: string } {
  if (lineBreak - lineStart < 2) return { ok: false, reason: 'line-too-short' };
  if (buffer[lineStart + 1] !== 0x3d) return { ok: false, reason: 'missing-equals' };

  const type = decodeLatin1Span(buffer, spanOf(lineStart, lineStart + 1));
  let valueStart = lineStart + 2;
  let valueEnd = lineBreak;
  while (valueEnd > valueStart && (buffer[valueEnd - 1] === 0x0d || buffer[valueEnd - 1] === 0x0a)) {
    valueEnd--;
  }
  valueStart = skipSpaces(buffer, valueStart, valueEnd);
  while (valueEnd > valueStart && (buffer[valueEnd - 1] === 0x20 || buffer[valueEnd - 1] === 0x09)) {
    valueEnd--;
  }

  return { ok: true, type, valueStart, valueEnd };
}

export function parseAttributeNameValue(
  buffer: Uint8Array,
  valueStart: number,
  valueEnd: number,
): { readonly nameSpan: ByteSpan; readonly valueSpan: ByteSpan } {
  const colon = findByteInRange(buffer, valueStart, valueEnd, 0x3a);
  if (colon > valueStart) {
    return {
      nameSpan: spanOf(valueStart, colon),
      valueSpan: spanOf(colon + 1, valueEnd),
    };
  }
  const space = findByteInRange(buffer, valueStart, valueEnd, 0x20);
  if (space > valueStart) {
    return {
      nameSpan: spanOf(valueStart, space),
      valueSpan: spanOf(skipSpaces(buffer, space + 1, valueEnd), valueEnd),
    };
  }
  return {
    nameSpan: spanOf(valueStart, valueEnd),
    valueSpan: spanOf(valueEnd, valueEnd),
  };
}

function findByteInRange(buffer: Uint8Array, start: number, end: number, byte: number): number {
  for (let i = start; i < end; i++) {
    if (buffer[i] === byte) return i;
  }
  return -1;
}

export function iterateSdpLines(
  buffer: Uint8Array,
  offset: number,
  end: number,
  onLine: (lineStart: number, lineBreak: number) => void,
): number {
  let cursor = offset;
  let lineCount = 0;
  while (cursor < end) {
    const lineBreak = findLineBreak(buffer, cursor, end);
    if (!isEmptyLine(buffer, cursor, lineBreak)) {
      onLine(cursor, lineBreak);
      lineCount++;
    }
    const term = lineTerminatorLength(buffer, lineBreak, end);
    if (term === 0 && lineBreak >= end) break;
    cursor = lineBreak + term;
  }
  return lineCount;
}

export function splitPortSpec(
  buffer: Uint8Array,
  portStart: number,
  portEnd: number,
): { readonly port: ByteSpan; readonly portCount: ByteSpan | null } {
  const slash = findByteInRange(buffer, portStart, portEnd, 0x2f);
  if (slash > portStart) {
    return {
      port: spanOf(portStart, slash),
      portCount: spanOf(slash + 1, portEnd),
    };
  }
  return { port: spanOf(portStart, portEnd), portCount: null };
}
