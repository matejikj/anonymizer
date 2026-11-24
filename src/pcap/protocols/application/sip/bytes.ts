/**
 * Byte-level helpers for SIP parsing. Never throws.
 */

import type { ByteSpan } from './types';

const ASCII_DECODER = new TextDecoder('latin1');

export function sliceSpan(buffer: Uint8Array, span: ByteSpan): Uint8Array {
  return buffer.subarray(span.offset, span.offset + span.length);
}

/** Decode span as Latin-1 (1:1 byte→code unit) for ASCII SIP tokens. */
export function decodeLatin1Span(buffer: Uint8Array, span: ByteSpan): string {
  if (span.length === 0) return '';
  return ASCII_DECODER.decode(sliceSpan(buffer, span));
}

/** Decode span as UTF-8 for human-readable classification (display names, etc.). */
export function decodeUtf8Span(buffer: Uint8Array, span: ByteSpan): string {
  if (span.length === 0) return '';
  return new TextDecoder('utf-8', { fatal: false }).decode(sliceSpan(buffer, span));
}

export function isSpaceByte(b: number): boolean {
  return b === 0x20 || b === 0x09;
}

export function isLineEndAt(buffer: Uint8Array, index: number, end: number): 'crlf' | 'lf' | null {
  if (index >= end) return null;
  if (buffer[index] === 0x0a) return 'lf';
  if (buffer[index] === 0x0d && index + 1 < end && buffer[index + 1] === 0x0a) return 'crlf';
  return null;
}

/** Find end of line starting at `start`; returns index of first line-break byte. */
export function findLineBreak(buffer: Uint8Array, start: number, end: number): number {
  for (let i = start; i < end; i++) {
    const b = buffer[i]!;
    if (b === 0x0a || b === 0x0d) return i;
  }
  return end;
}

/** Byte length of line terminator at `index`, or 0 if none. */
export function lineTerminatorLength(buffer: Uint8Array, index: number, end: number): number {
  const kind = isLineEndAt(buffer, index, end);
  if (kind === 'crlf') return 2;
  if (kind === 'lf') return 1;
  return 0;
}

/** True when line at `lineStart` is empty (only whitespace before break). */
export function isEmptyLine(buffer: Uint8Array, lineStart: number, lineBreak: number): boolean {
  for (let i = lineStart; i < lineBreak; i++) {
    if (!isSpaceByte(buffer[i]!)) return false;
  }
  return true;
}

export function skipSpaces(buffer: Uint8Array, start: number, end: number): number {
  let i = start;
  while (i < end && isSpaceByte(buffer[i]!)) i++;
  return i;
}

export function findByte(buffer: Uint8Array, start: number, end: number, byte: number): number {
  for (let i = start; i < end; i++) {
    if (buffer[i] === byte) return i;
  }
  return -1;
}

/** Case-insensitive Latin-1 compare of buffer slice to ASCII literal. */
export function bytesEqualAsciiIgnoreCase(
  buffer: Uint8Array,
  start: number,
  end: number,
  literal: string,
): boolean {
  if (end - start !== literal.length) return false;
  for (let i = 0; i < literal.length; i++) {
    const a = buffer[start + i]!;
    const b = literal.charCodeAt(i);
    const upperA = a >= 0x61 && a <= 0x7a ? a - 0x20 : a;
    const upperB = b >= 0x61 && b <= 0x7a ? b - 0x20 : b;
    if (upperA !== upperB) return false;
  }
  return true;
}

export function isTokenChar(b: number): boolean {
  // RFC 3261 token = 1*token-char
  if (b >= 0x30 && b <= 0x39) return true; // DIGIT
  if (b >= 0x41 && b <= 0x5a) return true; // ALPHA upper
  if (b >= 0x61 && b <= 0x7a) return true; // ALPHA lower
  switch (b) {
    case 0x2d: // -
    case 0x2e: // .
    case 0x21: // !
    case 0x25: // %
    case 0x2a: // *
    case 0x5f: // _
    case 0x2b: // +
    case 0x60: // `
    case 0x27: // '
    case 0x7e: // ~
    return true;
    default:
      return false;
  }
}

export function isMethodChar(b: number): boolean {
  return (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) || b === 0x2d;
}

export function spanOf(start: number, end: number): ByteSpan {
  return { offset: start, length: Math.max(0, end - start) };
}
