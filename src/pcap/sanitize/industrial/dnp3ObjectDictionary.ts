/**
 * T30 — DNP3 object group/variation value stride baseline (IEEE 1815 subset).
 */

export interface Dnp3ObjectStride {
  /** Octets per object value (excluding index prefix when qualifier adds one). */
  readonly valueSize: number
  readonly indexPrefixBytes: 0 | 1 | 2
}

/** Returns null when variation is outside baseline dictionary. */
export function dnp3ObjectStride(group: number, variation: number): Dnp3ObjectStride | null {
  if (group === 1) {
    if (variation === 1) return { valueSize: 1, indexPrefixBytes: 0 }
    if (variation === 2) return { valueSize: 2, indexPrefixBytes: 0 }
  }
  if (group === 30) {
    if (variation === 1) return { valueSize: 5, indexPrefixBytes: 0 }
    if (variation === 2) return { valueSize: 3, indexPrefixBytes: 0 }
    if (variation === 3) return { valueSize: 9, indexPrefixBytes: 0 }
    if (variation === 5) return { valueSize: 5, indexPrefixBytes: 0 }
  }
  if (group === 32) {
    if (variation === 1) return { valueSize: 5, indexPrefixBytes: 0 }
    if (variation === 2) return { valueSize: 3, indexPrefixBytes: 0 }
  }
  return null
}

export interface Dnp3QualifierRange {
  readonly objectCount: number
  readonly rangeBytes: number
  readonly indexPrefixBytes: 0 | 1 | 2
}

/** Parse object prefix / range field; null when qualifier unsupported. */
export function dnp3ParseQualifierRange(
  qualifier: number,
  buffer: Uint8Array,
  offset: number,
  end: number,
): Dnp3QualifierRange | null {
  switch (qualifier) {
    case 0x00:
      return { objectCount: 0, rangeBytes: 0, indexPrefixBytes: 0 }
    case 0x01:
      if (offset + 2 > end) return null
      return { objectCount: 0, rangeBytes: 2, indexPrefixBytes: 0 }
    case 0x02:
      if (offset + 4 > end) return null
      return { objectCount: 0, rangeBytes: 4, indexPrefixBytes: 0 }
    case 0x03:
      if (offset + 1 > end) return null
      return {
        objectCount: buffer[offset]!,
        rangeBytes: 1,
        indexPrefixBytes: 0,
      }
    case 0x04:
      if (offset + 2 > end) return null
      return {
        objectCount: buffer[offset]! | (buffer[offset + 1]! << 8),
        rangeBytes: 2,
        indexPrefixBytes: 0,
      }
    case 0x06:
      if (offset + 1 > end) return null
      return {
        objectCount: buffer[offset]!,
        rangeBytes: 1,
        indexPrefixBytes: 1,
      }
    case 0x07:
      if (offset + 1 > end) return null
      return {
        objectCount: buffer[offset]!,
        rangeBytes: 1,
        indexPrefixBytes: 2,
      }
    case 0x08:
      if (offset + 2 > end) return null
      return { objectCount: 0, rangeBytes: 2, indexPrefixBytes: 1 }
    case 0x09:
      if (offset + 4 > end) return null
      return { objectCount: 0, rangeBytes: 4, indexPrefixBytes: 2 }
    default:
      return null
  }
}
