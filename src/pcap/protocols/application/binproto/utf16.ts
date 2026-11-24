/**
 * T16 — length-preserving UTF-16LE/BE patch helpers (byte length stable, BMP ASCII-safe).
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector'
import { MappingPatchError } from '../../../anonymization/mappingErrors'

export type Utf16Endian = 'le' | 'be'

/**
 * Build replacement bytes of exactly `byteLength` (must be even).
 * Uses BMP ASCII code units from `replacement`; pads with ASCII space (0x0020).
 */
export function computeFixedLengthUtf16Bytes(
  byteLength: number,
  replacement: string,
  endian: Utf16Endian = 'le',
  padCodeUnit = 0x0020,
): Uint8Array {
  if (byteLength < 0 || byteLength % 2 !== 0) {
    throw new MappingPatchError('length-mismatch', `UTF-16 byteLength ${byteLength} must be even`)
  }
  const units = byteLength / 2
  const out = new Uint8Array(byteLength)
  for (let i = 0; i < units; i++) {
    const cu = i < replacement.length
      ? replacement.charCodeAt(i)! & 0xffff
      : padCodeUnit
    // Reject surrogate halves in replacement (no resize / no replacement char U+FFFD).
    if (cu >= 0xd800 && cu <= 0xdfff) {
      throw new MappingPatchError('length-mismatch', 'UTF-16 surrogate in replacement')
    }
    if (endian === 'le') {
      out[i * 2] = cu & 0xff
      out[i * 2 + 1] = (cu >> 8) & 0xff
    } else {
      out[i * 2] = (cu >> 8) & 0xff
      out[i * 2 + 1] = cu & 0xff
    }
  }
  return out
}

export function patchFixedLengthUtf16(
  collector: PatchCollector,
  offset: number,
  byteLength: number,
  replacement: string,
  endian: Utf16Endian = 'le',
): void {
  collector.add(offset, computeFixedLengthUtf16Bytes(byteLength, replacement, endian))
}

/** Decode UTF-16LE/BE buffer to JS string (BMP only; surrogates → null). */
export function decodeUtf16(
  bytes: Uint8Array,
  endian: Utf16Endian = 'le',
): string | null {
  if (bytes.length % 2 !== 0) return null
  let out = ''
  for (let i = 0; i < bytes.length; i += 2) {
    const cu = endian === 'le'
      ? bytes[i]! | (bytes[i + 1]! << 8)
      : (bytes[i]! << 8) | bytes[i + 1]!
    if (cu >= 0xd800 && cu <= 0xdfff) return null
    if (cu === 0) break
    out += String.fromCharCode(cu)
  }
  return out
}
