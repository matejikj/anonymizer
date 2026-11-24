/**
 * Proprietary radio-protocol SIP body (`application/vnd.*.radioprotocol`) — an LF-separated
 * `Key: Value` format (not CRLF like SIP headers) with one nested `MessageContent: {k: v, ...}`
 * map. Example shape:
 *
 *   MessageContentType: Subscription
 *   MessageContent: {Expire: 60, User: DISP UNIT15, SubscriptionId: 19679069611771353456366u15,
 *     UserLocation: testLocation}
 *   ServiceType: TextMessaging
 *   ProtocolVersion: RadioProtocol-1.8.0
 *   MessageType: Request
 *   MessageId: d52b2668-616b-4763-9991-daea150d089d
 *
 * `MessageContent` varies by `MessageContentType` — a `GroupChange` message instead carries
 * `{GroupName: '1001', GroupType: STATIC}`. Values are either bare tokens (may contain spaces,
 * e.g. "DISP UNIT15" — the field ends at the next top-level `,` or the closing `}`) or
 * single-quoted strings.
 *
 * Fail-closed throughout: anything that doesn't match this exact shape returns a parse
 * failure, and the caller (bodyPolicy.ts) falls back to the existing safe full-body redaction
 * — never guesses at an unfamiliar structure.
 */

import type { ByteSpan } from './types';
import { decodeLatin1Span } from './bytes';

/** Matches vendor radio-protocol SIP bodies without hardcoding a company MIME subtype. */
const RADIO_PROTOCOL_CONTENT_TYPE =
  /^application\/vnd\.[a-z0-9][a-z0-9._+-]*\.radioprotocol$/i;

export function looksLikeRadioProtocolBody(contentType: string | null): boolean {
  if (!contentType) return false;
  const base = contentType.trim().split(';')[0]?.trim() ?? '';
  return RADIO_PROTOCOL_CONTENT_TYPE.test(base);
}

export interface RadioProtocolOperation {
  readonly span: ByteSpan;
  readonly action: 'map' | 'redact';
  readonly mappingCategory: string | null;
  readonly canonicalText: string;
  readonly maskByte: number;
}

export const RADIO_PROTOCOL_MASK_BYTE = 0x2a; // '*', matches SIP_REDACT_MASK_BYTE

/** Top-level fields with no identity content — pass through unchanged. */
const PRESERVED_TOP_FIELDS = new Set([
  'MessageContentType',
  'ServiceType',
  'ProtocolVersion',
  'MessageType',
]);

/** `MessageId` is a correlation token, mapped the same way as SIP Call-ID. */
const CORRELATION_TOP_FIELDS = new Set(['MessageId']);

/** MessageContent nested fields with no identity content — pass through unchanged. */
const PRESERVED_CONTENT_FIELDS = new Set(['Expire', 'GroupType']);

/** MessageContent nested fields mapped to a specific identity category. */
const MAPPED_CONTENT_FIELDS: ReadonlyMap<string, string> = new Map([
  ['User', 'sip-user'],
  ['SubscriptionId', 'sip-token'],
  ['UserLocation', 'hostname'],
]);

interface KeyValueLine {
  readonly key: string;
  readonly valueSpan: ByteSpan;
}

interface ParsedRadioProtocolBody {
  readonly topFields: readonly KeyValueLine[];
  readonly contentFields: readonly KeyValueLine[] | null;
}

export type RadioProtocolParseResult =
  | { readonly ok: true; readonly body: ParsedRadioProtocolBody }
  | { readonly ok: false; readonly reason: string };

const KEY_CHAR = /[A-Za-z0-9_]/;

function isKeyChar(byte: number): boolean {
  return KEY_CHAR.test(String.fromCharCode(byte));
}

function isSpaceOrTab(byte: number): boolean {
  return byte === 0x20 || byte === 0x09;
}

function skipSpacesAndNewlines(buffer: Uint8Array, pos: number, end: number): number {
  while (pos < end && (isSpaceOrTab(buffer[pos]!) || buffer[pos] === 0x0a || buffer[pos] === 0x0d)) pos++;
  return pos;
}

function readKey(buffer: Uint8Array, pos: number, end: number): { key: string; next: number } | null {
  const start = pos;
  while (pos < end && isKeyChar(buffer[pos]!)) pos++;
  if (pos === start) return null;
  return { key: decodeLatin1Span(buffer, { offset: start, length: pos - start }), next: pos };
}

/** Finds the byte offset one past a matching `}` for the `{` at `openOffset`, or -1. */
function findMatchingBrace(buffer: Uint8Array, openOffset: number, end: number): number {
  let depth = 0;
  for (let i = openOffset; i < end; i++) {
    const b = buffer[i]!;
    if (b === 0x7b) depth++; // '{'
    else if (b === 0x7d) { // '}'
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Parses `key: value, key: value, ...` between `[start, end)` (the interior of a `{...}` map). */
function parseKeyValueEntries(buffer: Uint8Array, start: number, end: number): KeyValueLine[] | null {
  const entries: KeyValueLine[] = [];
  let pos = start;
  while (pos < end) {
    pos = skipSpacesAndNewlines(buffer, pos, end);
    if (pos >= end) break;
    const keyResult = readKey(buffer, pos, end);
    if (!keyResult) return null;
    pos = keyResult.next;
    if (buffer[pos] !== 0x3a) return null; // ':'
    pos++;
    pos = skipSpacesAndNewlines(buffer, pos, end);

    let valueSpan: ByteSpan;
    if (buffer[pos] === 0x27) { // single-quoted string
      const quoteStart = pos + 1;
      let quoteEnd = quoteStart;
      while (quoteEnd < end && buffer[quoteEnd] !== 0x27) quoteEnd++;
      if (quoteEnd >= end) return null; // unterminated quote
      valueSpan = { offset: quoteStart, length: quoteEnd - quoteStart };
      pos = quoteEnd + 1;
    } else {
      // Bare token — may contain spaces (e.g. "DISP UNIT15") — read to the next top-level ','
      // (this map has no nested '{' in any observed sample; a nested brace here is treated as
      // unfamiliar structure, not guessed at). `end` is the caller-supplied closing '}'
      // position itself (exclusive), so the LAST entry's value legitimately runs all the way
      // to `end` without ever seeing a stop character — that is success, not failure.
      const valueStart = pos;
      let valueEnd = pos;
      while (valueEnd < end && buffer[valueEnd] !== 0x2c) {
        if (buffer[valueEnd] === 0x7b || buffer[valueEnd] === 0x7d) return null; // unexpected brace
        valueEnd++;
      }
      // Trim trailing whitespace/newlines from the captured raw span.
      let trimmedEnd = valueEnd;
      while (trimmedEnd > valueStart && (isSpaceOrTab(buffer[trimmedEnd - 1]!) || buffer[trimmedEnd - 1] === 0x0a || buffer[trimmedEnd - 1] === 0x0d)) trimmedEnd--;
      if (trimmedEnd <= valueStart) return null; // empty value
      valueSpan = { offset: valueStart, length: trimmedEnd - valueStart };
      pos = valueEnd;
    }
    entries.push({ key: keyResult.key, valueSpan });

    pos = skipSpacesAndNewlines(buffer, pos, end);
    if (pos < end && buffer[pos] === 0x2c) { pos++; continue; }
    if (pos < end && buffer[pos] === 0x7d) break; // caller consumes the closing brace itself
    if (pos >= end) break;
    return null; // trailing garbage before the next entry/close
  }
  return entries;
}

export function parseRadioProtocolBody(buffer: Uint8Array, bodySpan: ByteSpan): RadioProtocolParseResult {
  const bodyStart = bodySpan.offset;
  const bodyEnd = bodySpan.offset + bodySpan.length;
  let pos = bodyStart;
  const topFields: KeyValueLine[] = [];
  let contentFields: KeyValueLine[] | null = null;
  let sawMessageContent = false;

  while (pos < bodyEnd) {
    while (pos < bodyEnd && buffer[pos] === 0x0a) pos++; // skip stray blank lines
    if (pos >= bodyEnd) break;

    const keyResult = readKey(buffer, pos, bodyEnd);
    if (!keyResult) return { ok: false, reason: 'expected-key' };
    pos = keyResult.next;
    if (buffer[pos] !== 0x3a) return { ok: false, reason: `expected-colon-after:${keyResult.key}` };
    pos++;
    while (pos < bodyEnd && isSpaceOrTab(buffer[pos]!)) pos++;

    if (keyResult.key === 'MessageContent') {
      if (buffer[pos] !== 0x7b) return { ok: false, reason: 'message-content-not-a-map' };
      const closeOffset = findMatchingBrace(buffer, pos, bodyEnd);
      if (closeOffset < 0) return { ok: false, reason: 'message-content-unbalanced-braces' };
      const entries = parseKeyValueEntries(buffer, pos + 1, closeOffset);
      if (entries === null) return { ok: false, reason: 'message-content-parse-failed' };
      contentFields = entries;
      sawMessageContent = true;
      pos = closeOffset + 1;
    } else {
      const valueStart = pos;
      let valueEnd = valueStart;
      while (valueEnd < bodyEnd && buffer[valueEnd] !== 0x0a) valueEnd++;
      let trimmedEnd = valueEnd;
      while (trimmedEnd > valueStart && buffer[trimmedEnd - 1] === 0x0d) trimmedEnd--;
      if (trimmedEnd <= valueStart) return { ok: false, reason: `empty-value:${keyResult.key}` };
      topFields.push({ key: keyResult.key, valueSpan: { offset: valueStart, length: trimmedEnd - valueStart } });
      pos = valueEnd;
    }

    if (pos < bodyEnd && buffer[pos] === 0x0a) { pos++; continue; }
    if (pos >= bodyEnd) break;
    return { ok: false, reason: 'unexpected-trailing-content' };
  }

  if (topFields.length === 0 && !sawMessageContent) return { ok: false, reason: 'empty-body' };
  return { ok: true, body: { topFields, contentFields } };
}

export function buildRadioProtocolBodyPlan(
  buffer: Uint8Array,
  bodySpan: ByteSpan,
): { ok: true; operations: readonly RadioProtocolOperation[] } | { ok: false; reason: string } {
  const parsed = parseRadioProtocolBody(buffer, bodySpan);
  if (!parsed.ok) return parsed;

  const operations: RadioProtocolOperation[] = [];
  const push = (span: ByteSpan, action: 'map' | 'redact', mappingCategory: string | null, canonicalText: string) => {
    operations.push({ span, action, mappingCategory, canonicalText, maskByte: RADIO_PROTOCOL_MASK_BYTE });
  };

  for (const field of parsed.body.topFields) {
    if (PRESERVED_TOP_FIELDS.has(field.key)) continue;
    if (CORRELATION_TOP_FIELDS.has(field.key)) {
      push(field.valueSpan, 'map', 'sip-call-id', decodeLatin1Span(buffer, field.valueSpan));
      continue;
    }
    // Unrecognized top-level field — safe default is redaction, not a guess at its sensitivity.
    push(field.valueSpan, 'redact', null, '');
  }

  for (const field of parsed.body.contentFields ?? []) {
    if (PRESERVED_CONTENT_FIELDS.has(field.key)) continue;
    const mappedCategory = MAPPED_CONTENT_FIELDS.get(field.key);
    if (mappedCategory) {
      push(field.valueSpan, 'map', mappedCategory, decodeLatin1Span(buffer, field.valueSpan));
      continue;
    }
    push(field.valueSpan, 'redact', null, '');
  }

  return { ok: true, operations };
}
