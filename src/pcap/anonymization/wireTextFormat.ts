/**
 * CF-02 — length-stable text wire aliases derived from mapped wire values.
 */

import type { IdentityCategory } from '../../mapping/identityCategories';
import { maskAlphanumeric } from '../../mapping/textAliasEngine';
import { MappingLookupError } from './mappingErrors';

/** Replace digits in originalSpelling while preserving delimiters (+, -, spaces, parens). */
export function maskDigitsPreservingFormat(originalSpelling: string, mappedDigits: string): string {
  if (mappedDigits.length === 0) {
    throw new MappingLookupError('representation-unavailable', { category: 'sip-phone' });
  }
  let digitIndex = 0;
  return Array.from(originalSpelling).map((ch) => {
    if (/\d/.test(ch)) {
      const mapped = mappedDigits[digitIndex % mappedDigits.length] ?? '0';
      digitIndex++;
      return mapped;
    }
    return ch;
  }).join('');
}

/** Format mapped port number into the same text shape as originalSpelling (digit count / prefix). */
export function formatPortTextFromWire(mappedPort: number, originalSpelling: string): string {
  const digitSlots = originalSpelling.replace(/\D/g, '').length;
  if (digitSlots === 0) {
    throw new MappingLookupError('representation-unavailable', { category: 'port' });
  }
  const max = 10 ** digitSlots - 1;
  if (mappedPort > max) {
    const min = Math.max(1024, 1);
    mappedPort = min + (mappedPort % (max - min + 1));
  }
  const digits = String(mappedPort).padStart(digitSlots, '0');
  let digitIndex = 0;
  const out = Array.from(originalSpelling).map((ch) => {
    if (/\d/.test(ch)) {
      return digits[digitIndex++] ?? '0';
    }
    return ch;
  }).join('');
  if (out.length !== originalSpelling.length) {
    throw new MappingLookupError('length-mismatch', { category: 'port' });
  }
  return out;
}

/** Use mapped IPv4 when it already fits; otherwise derive a valid IPv4 of exact byteLength. */
export function formatIpv4TextFromWire(mappedIp: string, byteLength: number): string {
  if (mappedIp.length === byteLength) return mappedIp;
  const parts = mappedIp.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    throw new MappingLookupError('representation-unavailable', { category: 'ipv4' });
  }
  // First choice: re-spell the SAME numeric value with per-octet zero-padding, so every other
  // occurrence (binary header, other text spellings) of this pseudonym still reads as one address.
  const repadded = repadIpv4ToLength(parts as [number, number, number, number], byteLength);
  if (repadded) return repadded;
  // The target length is outside anything a zero-padded spelling of this value can reach (this
  // scheme's fixed base octets alone need ~10-15 chars). Derive an independent, deterministic,
  // exact-length, always-valid IPv4 literal instead of corrupting the original spelling.
  return deriveExactLengthIpv4(mappedIp, byteLength);
}

/** Re-spells a fixed IPv4 value's octets with leading zeros to hit an exact total length, if possible. */
function repadIpv4ToLength(parts: readonly [number, number, number, number], byteLength: number): string | null {
  const digitsTarget = byteLength - 3; // 3 dots
  const natural = parts.map((p) => String(p).length);
  const naturalSum = natural.reduce((a, b) => a + b, 0);
  if (digitsTarget < naturalSum || digitsTarget > 12) return null;
  const widths = [...natural];
  let remaining = digitsTarget - naturalSum;
  for (let i = 0; i < 4 && remaining > 0; i++) {
    const room = 3 - widths[i]!;
    const take = Math.min(room, remaining);
    widths[i] = widths[i]! + take;
    remaining -= take;
  }
  if (remaining > 0) return null;
  return parts.map((p, i) => String(p).padStart(widths[i]!, '0')).join('.');
}

/** Deterministically derives a valid, exact-length IPv4 literal when no re-padding of the mapped value reaches it. */
function deriveExactLengthIpv4(seed: string, byteLength: number): string {
  const digitsTarget = byteLength - 3;
  if (digitsTarget < 4 || digitsTarget > 12) {
    throw new MappingLookupError('representation-unavailable', { category: 'ipv4' });
  }
  const widths: number[] = [];
  let remaining = digitsTarget;
  for (let i = 0; i < 4; i++) {
    const slotsLeft = 4 - i - 1;
    const maxHere = Math.min(3, remaining - slotsLeft);
    const minHere = Math.max(1, remaining - slotsLeft * 3);
    const width = minHere + (hashByte(seed, i) % (maxHere - minHere + 1));
    widths.push(width);
    remaining -= width;
  }
  const parts = widths.map((w, i) => {
    const min = w === 1 ? 0 : 10 ** (w - 1);
    const max = w === 3 ? 255 : 10 ** w - 1;
    const value = min + (hashByte(seed, i + 4) % (max - min + 1));
    return String(value);
  });
  return parts.join('.');
}

function hashByte(seed: string, salt: number): number {
  let h = (0x811c9dc5 ^ salt) >>> 0;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h % 256;
}

/**
 * A hash-derived (not a literal reuse of wireAlias's own characters) pseudorandom hex
 * stream. IPv6 pseudonyms and captured "documentation" test/example addresses both commonly
 * start with the same literal prefix (2001:db8::/32, RFC 3849) — cycling wireAlias's own
 * colon-stripped digits straight into originalSpelling's digit slots would silently echo that
 * shared prefix back out unchanged. Hashing first decorrelates the fill from the original text.
 */
function expandHexStream(seed: string, minLength: number): string {
  const alphabet = '0123456789abcdef';
  let state = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    state ^= seed.charCodeAt(i);
    state = Math.imul(state, 0x01000193) >>> 0;
  }
  if (state === 0) state = 0x9e3779b9;
  let out = '';
  while (out.length < minLength) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out += alphabet[state % alphabet.length];
  }
  return out;
}

/** Derive a length-stable text alias from the primary wire alias (snapshot adapter + SessionMapping). */
export function formatTextAliasFromWire(
  category: IdentityCategory,
  wireAlias: string,
  byteLength: number,
  originalSpelling: string,
): string {
  let textAlias: string;
  switch (category) {
    case 'ipv4':
      try {
        textAlias = formatIpv4TextFromWire(wireAlias, byteLength);
      } catch {
        textAlias = maskAlphanumeric(originalSpelling, wireAlias.replace(/\D/g, 'x'));
      }
      break;
    case 'ipv6':
      textAlias = wireAlias.length === byteLength
        ? wireAlias
        : maskAlphanumeric(originalSpelling, expandHexStream(wireAlias, originalSpelling.length));
      break;
    case 'hostname':
      textAlias = wireAlias.length === byteLength
        ? wireAlias
        : maskAlphanumeric(originalSpelling, wireAlias.replace(/\./g, ''));
      break;
    case 'port': {
      const slash = wireAlias.indexOf('/');
      const mappedPort = Number.parseInt(wireAlias.slice(slash + 1), 10);
      textAlias = formatPortTextFromWire(mappedPort, originalSpelling);
      break;
    }
    case 'sip-phone':
      textAlias = maskDigitsPreservingFormat(originalSpelling, wireAlias.replace(/\D/g, '') || wireAlias);
      break;
    case 'sip-call-id':
    case 'sip-token':
    case 'sip-user':
      textAlias = maskAlphanumeric(originalSpelling, wireAlias);
      break;
    case 'sdp-session-id':
    case 'imsi':
    case 'imei':
      // Wire alias is already a same-length digit string from SessionMapping.
      textAlias = wireAlias.length === byteLength
        ? wireAlias
        : wireAlias.slice(0, byteLength).padStart(byteLength, '0');
      break;
    case 'snmp-engine-id':
      textAlias = wireAlias.length === byteLength
        ? wireAlias
        : wireAlias.slice(0, byteLength).padEnd(byteLength, 'f');
      break;
    case 'opaque-id':
      textAlias = wireAlias.length === byteLength
        ? wireAlias
        : maskAlphanumeric(originalSpelling, wireAlias);
      break;
    default:
      textAlias = wireAlias.length === byteLength
        ? wireAlias
        : maskAlphanumeric(originalSpelling, wireAlias);
  }
  if (textAlias.length !== byteLength) {
    throw new MappingLookupError('length-mismatch', { category });
  }
  return textAlias;
}
