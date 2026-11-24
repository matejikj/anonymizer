/**
 * SIP header line parser.
 */

import type { SipParseLimits } from './limits';
import type { SipHeader } from './types';
import {
  decodeLatin1Span,
  decodeUtf8Span,
  findByte,
  isSpaceByte,
  isTokenChar,
  spanOf,
} from './bytes';
import { canonicalizeHeaderName } from './compact';
import { parseHeaderParameters, trimValueBounds } from './uri';

export type HeaderParseResult =
  | { readonly ok: true; readonly header: SipHeader }
  | { readonly ok: false; readonly reason: string };

export function parseHeaderLine(
  buffer: Uint8Array,
  lineStart: number,
  lineBreak: number,
  limits: SipParseLimits,
): HeaderParseResult {
  const lineLength = lineBreak - lineStart;
  if (lineLength <= 0) return { ok: false, reason: 'empty-header' };
  if (lineLength > limits.maxLineBytes) return { ok: false, reason: 'header-line-too-long' };

  const colon = findByte(buffer, lineStart, lineBreak, 0x3a);
  if (colon <= lineStart) return { ok: false, reason: 'header-missing-colon' };

  const nameSpan = spanOf(lineStart, colon);
  if (nameSpan.length > limits.maxHeaderNameBytes) return { ok: false, reason: 'header-name-too-long' };
  for (let i = lineStart; i < colon; i++) {
    const b = buffer[i]!;
    if (!isTokenChar(b)) return { ok: false, reason: 'header-name-char' };
  }

  let valueStart = colon + 1;
  while (valueStart < lineBreak && (buffer[valueStart] === 0x20 || buffer[valueStart] === 0x09)) {
    valueStart++;
  }
  let valueEnd = lineBreak;
  while (valueEnd > valueStart && (buffer[valueEnd - 1] === 0x0d || buffer[valueEnd - 1] === 0x0a)) {
    valueEnd--;
  }

  const trimmed = trimValueBounds(buffer, valueStart, valueEnd);
  const valueSpan = spanOf(trimmed.start, trimmed.end);
  const paramZoneStart = headerParameterZoneStart(buffer, trimmed.start, trimmed.end);
  if (paramZoneStart === null) return { ok: false, reason: 'header-name-addr-unterminated' };
  const params = parseHeaderParameters(buffer, paramZoneStart, trimmed.end, limits);
  if (!params.ok) return { ok: false, reason: params.reason };

  const nameText = decodeLatin1Span(buffer, nameSpan);
  const canonicalNameText = canonicalizeHeaderName(nameText);
  const valueText = decodeUtf8Span(buffer, valueSpan);

  return {
    ok: true,
    header: {
      span: spanOf(lineStart, lineBreak),
      name: nameSpan,
      nameText,
      canonicalNameText,
      value: valueSpan,
      valueText,
      parameters: params.parameters,
    },
  };
}

/** Append a RFC 3261 folded continuation line (leading SP/TAB) to a header. */
export function appendFoldedContinuation(
  buffer: Uint8Array,
  header: SipHeader,
  foldLineStart: number,
  foldLineBreak: number,
  limits: SipParseLimits,
): HeaderParseResult {
  const foldLineLen = foldLineBreak - foldLineStart;
  if (foldLineLen <= 0) return { ok: false, reason: 'empty-folded-line' };
  if (foldLineLen > limits.maxLineBytes) return { ok: false, reason: 'header-line-too-long' };
  if (!isSpaceByte(buffer[foldLineStart]!)) return { ok: false, reason: 'not-folded-continuation' };

  let contentStart = foldLineStart;
  while (contentStart < foldLineBreak && isSpaceByte(buffer[contentStart]!)) {
    contentStart++;
  }

  const foldedText = decodeUtf8Span(buffer, spanOf(contentStart, foldLineBreak));
  const valueText = `${header.valueText.trimEnd()} ${foldedText}`;
  const newValueSpan = spanOf(header.value.offset, foldLineBreak);
  const trimmed = trimValueBounds(buffer, header.value.offset, foldLineBreak);
  const paramZoneStart = headerParameterZoneStart(buffer, trimmed.start, trimmed.end);
  if (paramZoneStart === null) return { ok: false, reason: 'header-name-addr-unterminated' };
  const params = parseHeaderParameters(buffer, paramZoneStart, trimmed.end, limits);
  if (!params.ok) return { ok: false, reason: params.reason };

  return {
    ok: true,
    header: {
      span: spanOf(header.span.offset, foldLineBreak),
      name: header.name,
      nameText: header.nameText,
      canonicalNameText: header.canonicalNameText,
      value: newValueSpan,
      valueText,
      parameters: params.parameters,
    },
  };
}

export function headerNameEquals(header: SipHeader, name: string): boolean {
  return header.canonicalNameText === canonicalizeHeaderName(name);
}

/**
 * Header-level parameters (contact-params, addr-params, ...) start after a name-addr's
 * closing `>`, never inside it — a `;` before that point belongs to the embedded URI's own
 * uri-parameters, parsed separately by `parseSipUri`. Without this, a value like
 * `"Alice" <sip:a@b;ob>` would let the closing `>` leak into the header-level parameter
 * name and be rejected as an invalid token character. Returns null for an unterminated
 * name-addr (`<` with no matching `>`).
 */
function headerParameterZoneStart(buffer: Uint8Array, start: number, end: number): number | null {
  const laquot = findByte(buffer, start, end, 0x3c); // '<'
  if (laquot < 0) return start;
  const raquot = findByte(buffer, laquot + 1, end, 0x3e); // '>'
  if (raquot < 0) return null;
  return raquot + 1;
}
