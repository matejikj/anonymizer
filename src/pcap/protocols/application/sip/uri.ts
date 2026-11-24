/**
 * SIP / SIPS / TEL URI parser with byte-accurate spans.
 * CF-06: bracketed IPv6 hosts are parsed without treating interior `:` as a port separator.
 */

import type { SipParseLimits } from './limits';
import type { SipParameter, SipUri } from './types';
import {
  decodeLatin1Span,
  findByte,
  isTokenChar,
  skipSpaces,
  spanOf,
} from './bytes';

export type UriParseResult =
  | { readonly ok: true; readonly uri: SipUri }
  | { readonly ok: false; readonly reason: string };

export function parseSipUri(
  buffer: Uint8Array,
  start: number,
  end: number,
  limits: SipParseLimits,
): UriParseResult {
  const uriStart = start;
  const uriEnd = end;
  const uriLength = uriEnd - uriStart;
  if (uriLength <= 0 || uriLength > limits.maxUriBytes) {
    return { ok: false, reason: 'uri-length' };
  }

  const colon = findByte(buffer, start, end, 0x3a);
  if (colon <= start) return { ok: false, reason: 'uri-scheme' };

  const schemeSpan = spanOf(start, colon);
  const scheme = decodeLatin1Span(buffer, schemeSpan).toLowerCase();
  if (scheme !== 'sip' && scheme !== 'sips' && scheme !== 'tel') {
    return { ok: false, reason: 'uri-scheme-unsupported' };
  }

  let cursor = colon + 1;
  let user: ReturnType<typeof spanOf> | null = null;
  let password: ReturnType<typeof spanOf> | null = null;
  let hostStart = cursor;
  let hostEnd = end;
  let port: ReturnType<typeof spanOf> | null = null;

  const at = findByte(buffer, cursor, end, 0x40);
  const semi = findByte(buffer, cursor, end, 0x3b);
  const question = findByte(buffer, cursor, end, 0x3f);
  const hostRegionEnd = earliestPositive(semi, question, end);

  if (scheme === 'tel') {
    hostStart = cursor;
    hostEnd = hostRegionEnd;
  } else {
    if (at >= 0 && at < hostRegionEnd) {
      const userPartStart = cursor;
      const userPartEnd = at;
      const colonInUser = findByte(buffer, userPartStart, userPartEnd, 0x3a);
      if (colonInUser >= 0) {
        user = spanOf(userPartStart, colonInUser);
        password = spanOf(colonInUser + 1, userPartEnd);
      } else {
        user = spanOf(userPartStart, userPartEnd);
      }
      cursor = at + 1;
      hostStart = cursor;
    }

    if (buffer[hostStart] === 0x5b) {
      // Bracketed IPv6 reference: host is interior of [...]; brackets are not mapped.
      const close = findByte(buffer, hostStart + 1, hostRegionEnd, 0x5d);
      if (close < 0) return { ok: false, reason: 'uri-ipv6-bracket' };
      hostStart = hostStart + 1;
      hostEnd = close;
      if (hostEnd <= hostStart) return { ok: false, reason: 'uri-host' };

      const after = close + 1;
      if (after < hostRegionEnd && buffer[after] === 0x3a) {
        const portStart = after + 1;
        if (portStart >= hostRegionEnd) return { ok: false, reason: 'uri-port-empty' };
        const portResult = parsePortSpan(buffer, portStart, hostRegionEnd);
        if (!portResult.ok) return portResult;
        port = portResult.port;
      } else if (after < hostRegionEnd && after !== semi && after !== question) {
        return { ok: false, reason: 'uri-ipv6-suffix' };
      }
    } else {
      hostEnd = hostRegionEnd;
      const colonPort = findByte(buffer, hostStart, hostEnd, 0x3a);
      if (colonPort >= 0) {
        hostEnd = colonPort;
        if (colonPort + 1 >= hostRegionEnd) return { ok: false, reason: 'uri-port-empty' };
        const portResult = parsePortSpan(buffer, colonPort + 1, hostRegionEnd);
        if (!portResult.ok) return portResult;
        port = portResult.port;
      }
    }
  }

  if (hostEnd <= hostStart) return { ok: false, reason: 'uri-host' };

  const paramStart = semi >= 0 && (question < 0 || semi < question) ? semi + 1 : -1;
  const paramEnd = question >= 0 ? question : end;
  const params = paramStart >= 0
    ? parseParameters(buffer, paramStart, paramEnd, limits)
    : { ok: true as const, parameters: [] as const };
  if (!params.ok) return { ok: false, reason: params.reason };

  return {
    ok: true,
    uri: {
      span: spanOf(uriStart, end),
      scheme: schemeSpan,
      user,
      password,
      host: spanOf(hostStart, hostEnd),
      port,
      parameters: params.parameters,
    },
  };
}

function earliestPositive(a: number, b: number, fallback: number): number {
  const candidates = [a, b].filter((n) => n >= 0);
  if (candidates.length === 0) return fallback;
  return Math.min(...candidates);
}

function parsePortSpan(
  buffer: Uint8Array,
  start: number,
  end: number,
): { ok: true; port: ReturnType<typeof spanOf> } | { ok: false; reason: string } {
  if (end <= start) return { ok: false, reason: 'uri-port-empty' };
  for (let i = start; i < end; i++) {
    const b = buffer[i]!;
    if (b < 0x30 || b > 0x39) return { ok: false, reason: 'uri-port-nonnumeric' };
  }
  const text = decodeLatin1Span(buffer, spanOf(start, end));
  if (text.length === 0) return { ok: false, reason: 'uri-port-empty' };
  const value = Number.parseInt(text, 10);
  if (!Number.isInteger(value) || value < 0 || value > 65535) {
    return { ok: false, reason: 'uri-port-range' };
  }
  return { ok: true, port: spanOf(start, end) };
}

function parseParameters(
  buffer: Uint8Array,
  start: number,
  end: number,
  limits: SipParseLimits,
): { ok: true; parameters: readonly SipParameter[] } | { ok: false; reason: string } {
  if (start >= end) return { ok: true, parameters: [] };
  if (limits.maxParameterDepth < 1) {
    return { ok: false, reason: 'parameter-depth' };
  }

  const parameters: SipParameter[] = [];
  let cursor = start;
  while (cursor < end) {
    cursor = skipParamSeparators(buffer, cursor, end);
    if (cursor >= end) break;
    if (parameters.length >= limits.maxParameterCount) {
      return { ok: false, reason: 'parameter-count' };
    }
    const semi = findByte(buffer, cursor, end, 0x3b);
    const paramEnd = semi >= 0 ? semi : end;
    const parsed = parseOneParameter(buffer, cursor, paramEnd);
    if (!parsed.ok) return { ok: false, reason: parsed.reason };
    parameters.push(parsed.parameter);
    cursor = paramEnd;
    if (semi >= 0) cursor = semi + 1;
  }
  return { ok: true, parameters };
}

function parseOneParameter(
  buffer: Uint8Array,
  start: number,
  end: number,
): { ok: true; parameter: SipParameter } | { ok: false; reason: string } {
  const paramStart = skipParamSeparators(buffer, start, end);
  if (paramStart >= end) return { ok: false, reason: 'parameter-empty' };
  if (!isTokenChar(buffer[paramStart]!)) {
    return { ok: false, reason: 'parameter-name' };
  }
  // RFC 3261 generic-param = token [ "=" gen-value ]; the "=" is optional, so reaching
  // `end` without one (a flag parameter like `;rport`, `;ob`, `;lr`) is valid, not an error.
  let nameEnd = paramStart;
  while (nameEnd < end && buffer[nameEnd] !== 0x3d) nameEnd++;
  for (let i = paramStart + 1; i < nameEnd; i++) {
    if (!isTokenChar(buffer[i]!)) return { ok: false, reason: 'parameter-name' };
  }
  const name = spanOf(paramStart, nameEnd);
  let value: ReturnType<typeof spanOf> | null = null;
  if (nameEnd < end && buffer[nameEnd] === 0x3d) {
    const valueStart = nameEnd + 1;
    if (valueStart >= end) return { ok: false, reason: 'parameter-value' };
    value = spanOf(valueStart, end);
  }
  return {
    ok: true,
    parameter: {
      span: spanOf(paramStart, end),
      name,
      value,
    },
  };
}

/** Skip SP/TAB/CR/LF between folded header parameter segments. */
function skipParamSeparators(buffer: Uint8Array, start: number, end: number): number {
  let cursor = start;
  while (cursor < end) {
    const b = buffer[cursor]!;
    if (b === 0x20 || b === 0x09 || b === 0x0d || b === 0x0a) {
      cursor++;
      continue;
    }
    break;
  }
  return cursor;
}

/** Parse semicolon parameters inside a header value (after the primary value token). */
export function parseHeaderParameters(
  buffer: Uint8Array,
  start: number,
  end: number,
  limits: SipParseLimits,
): { ok: true; parameters: readonly SipParameter[] } | { ok: false; reason: string } {
  const semi = findByte(buffer, start, end, 0x3b);
  if (semi < 0) return { ok: true, parameters: [] };
  return parseParameters(buffer, semi + 1, end, limits);
}

/** Trim leading/trailing spaces around a header value primary token. */
export function trimValueBounds(buffer: Uint8Array, start: number, end: number): { start: number; end: number } {
  let s = skipSpaces(buffer, start, end);
  let e = end;
  while (e > s && isSpaceByte(buffer[e - 1]!)) e--;
  return { start: s, end: e };
}

function isSpaceByte(b: number): boolean {
  return b === 0x20 || b === 0x09;
}
