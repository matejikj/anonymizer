/**
 * T59 — Mobile Identity / 5GS mobile identity / SUCI helpers (TS 24.008 / 24.301 / 24.501).
 * TBCD via T16; GUTI/TMSI structured opaque map; SUCI concealed → mask.
 */

import {
  decodeTbcd,
  encodeTbcd,
  remapTbcdBytes,
  normalizeImsiDigits,
  normalizeImeiDigits,
  TBCD_GSM,
} from '../application/binproto/tbcd.ts'

export type NasIdentityKind =
  | 'imsi'
  | 'imei'
  | 'imeisv'
  | 'tmsi'
  | 'guti'
  | 'suci-scheme0'
  | 'suci-concealed'
  | 'unknown'

export interface NasIdentityView {
  readonly kind: NasIdentityKind
  /** TBCD digit payload offset/length (after type nibble byte), if applicable. */
  readonly digitsOffset: number
  readonly digitsLength: number
  readonly digits: string | null
  /** Whole identity value span (including type byte). */
  readonly valueOffset: number
  readonly valueLength: number
}

/**
 * Parse EPS/5GS Mobile Identity value bytes (LV contents, no IEI/length).
 * First byte: odd/even indicator | type of identity (low 3 bits).
 */
export function parseMobileIdentityValue(
  buffer: Uint8Array,
  offset: number,
  length: number,
): NasIdentityView | null {
  if (length < 1) return null
  const typeByte = buffer[offset]!
  const idType = typeByte & 0x07
  const digitsOffset = offset + 1
  const digitsLength = length - 1

  switch (idType) {
    case 1: {
      // IMSI — type nibble encodes first digit in high nibble when odd/even
      const digits = decodeMobileIdentityDigits(buffer, offset, length)
      return {
        kind: 'imsi',
        digitsOffset: offset,
        digitsLength: length,
        digits,
        valueOffset: offset,
        valueLength: length,
      }
    }
    case 2: {
      const digits = decodeMobileIdentityDigits(buffer, offset, length)
      return {
        kind: 'imei',
        digitsOffset: offset,
        digitsLength: length,
        digits,
        valueOffset: offset,
        valueLength: length,
      }
    }
    case 3: {
      const digits = decodeMobileIdentityDigits(buffer, offset, length)
      return {
        kind: 'imeisv',
        digitsOffset: offset,
        digitsLength: length,
        digits,
        valueOffset: offset,
        valueLength: length,
      }
    }
    case 4:
      return {
        kind: 'tmsi',
        digitsOffset: digitsOffset,
        digitsLength: digitsLength,
        digits: null,
        valueOffset: offset,
        valueLength: length,
      }
    case 6:
      // GUTI / 5G-GUTI structured
      return {
        kind: 'guti',
        digitsOffset: digitsOffset,
        digitsLength: digitsLength,
        digits: null,
        valueOffset: offset,
        valueLength: length,
      }
    default:
      return {
        kind: 'unknown',
        digitsOffset: digitsOffset,
        digitsLength: digitsLength,
        digits: null,
        valueOffset: offset,
        valueLength: length,
      }
  }
}

/**
 * Decode IMSI/IMEI digits from Mobile Identity encoding
 * (first digit in high nibble of type byte when present).
 */
export function decodeMobileIdentityDigits(
  buffer: Uint8Array,
  offset: number,
  length: number,
): string | null {
  if (length < 1) return null
  const typeByte = buffer[offset]!
  const oddEven = (typeByte >> 3) & 0x01
  const firstDigit = (typeByte >> 4) & 0x0f
  let digits = ''
  if (firstDigit <= 9) digits += String(firstDigit)
  else if (firstDigit !== 0x0f) return null
  if (length > 1) {
    const rest = decodeTbcd(buffer.subarray(offset + 1, offset + length), TBCD_GSM)
    if (rest === null) return null
    digits += rest
  }
  // oddEven=0 means even number of digits → last is filler already handled by TBCD
  void oddEven
  return digits.length > 0 ? digits : null
}

export function normalizeIdentityDigits(
  kind: NasIdentityKind,
  digits: string,
): string | null {
  if (kind === 'imsi') return normalizeImsiDigits(digits)
  if (kind === 'imei' || kind === 'imeisv') return normalizeImeiDigits(digits)
  return null
}

export function remapMobileIdentityDigits(
  original: Uint8Array,
  aliasDigits: string,
): Uint8Array | null {
  if (original.length < 1) return null
  const typeByte = original[0]!
  const idType = typeByte & 0x07
  const oddEven = (typeByte >> 3) & 0x01
  if (aliasDigits.length === 0) return null
  const first = aliasDigits.charCodeAt(0) - 48
  if (first < 0 || first > 9) return null
  const out = original.slice()
  out[0] = (first << 4) | (oddEven << 3) | idType
  if (original.length === 1) return out
  const restDigits = aliasDigits.slice(1)
  const restLen = original.length - 1
  const remapped = remapTbcdBytes(original.subarray(1), restDigits, TBCD_GSM)
  if (remapped) {
    out.set(remapped, 1)
    return out
  }
  const encoded = encodeTbcd(restDigits, restLen, TBCD_GSM)
  if (!encoded) return null
  out.set(encoded, 1)
  return out
}

/**
 * 5GS SUCI (TS 24.501): scheme output after SUPI format + home network fields.
 * schemeId 0 = null scheme (IMSI in clear → treat as scheme0 identity).
 * Other schemes → concealed payload mask.
 */
export function classifySuciValue(
  buffer: Uint8Array,
  offset: number,
  length: number,
): { kind: 'suci-scheme0' | 'suci-concealed'; schemeId: number } | null {
  if (length < 2) return null
  // Simplified: byte0 SUPI format, byte1 protection scheme id (low nibble)
  const schemeId = buffer[offset + 1]! & 0x0f
  if (schemeId === 0) return { kind: 'suci-scheme0', schemeId }
  return { kind: 'suci-concealed', schemeId }
}
