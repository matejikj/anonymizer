/**
 * T43 — text source encoding detection and decode labels (WHATWG Encoding).
 * BOM / UTF-16 NUL parity / CP1250 vs ISO-8859-2 heuristics; no silent data loss.
 */

export const TEXT_ENCODING_LABELS = [
  'utf-8',
  'windows-1250',
  'iso-8859-2',
  'utf-16le',
  'utf-16be',
] as const

export type TextEncodingLabel = (typeof TEXT_ENCODING_LABELS)[number]

export type EncodingConfidence = 'bom' | 'high' | 'medium' | 'low'

export interface TextEncodingDetection {
  readonly label: TextEncodingLabel
  readonly confidence: EncodingConfidence
  /** Bytes to skip after BOM (0 when none). */
  readonly bomLength: number
  readonly candidates: readonly TextEncodingLabel[]
  readonly note?: string
}

/** CP1250 high bytes that commonly appear in Czech prose (not ISO-8859-2). */
const CP1250_CZECH_BYTES = new Set([
  0x8a, 0x8d, 0x8e, 0x9a, 0x9d, 0x9e, // Š Ť Ž š ť ž
  0xc0, 0xc8, 0xc9, 0xcc, 0xd2, 0xd8, 0xda, 0xdd, // Á Č É Ě Ó Ř Ú Ý
  0xe0, 0xe8, 0xe9, 0xec, 0xf2, 0xf8, 0xfa, 0xfd, // á č é ě ó ř ú ý
])

/** ISO-8859-2 Czech-leaning bytes distinct from CP1250 for the same glyphs. */
const LATIN2_CZECH_BYTES = new Set([
  0xa9, 0xab, 0xae, 0xb9, 0xbb, 0xbe, // Š Ť Ž š ť ž (Latin-2)
  0xc1, 0xc8, 0xc9, 0xcc, 0xd3, 0xd8, 0xda, 0xdd,
  0xe1, 0xe8, 0xe9, 0xec, 0xf3, 0xf8, 0xfa, 0xfd,
])

export function isTextEncodingLabel(value: string): value is TextEncodingLabel {
  return (TEXT_ENCODING_LABELS as readonly string[]).includes(value)
}

export function detectTextEncoding(head: Uint8Array): TextEncodingDetection {
  if (head.byteLength >= 3 && head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf) {
    return {
      label: 'utf-8',
      confidence: 'bom',
      bomLength: 3,
      candidates: ['utf-8'],
      note: 'BOM UTF-8',
    }
  }
  if (head.byteLength >= 2 && head[0] === 0xff && head[1] === 0xfe) {
    return {
      label: 'utf-16le',
      confidence: 'bom',
      bomLength: 2,
      candidates: ['utf-16le'],
      note: 'BOM UTF-16 LE',
    }
  }
  if (head.byteLength >= 2 && head[0] === 0xfe && head[1] === 0xff) {
    return {
      label: 'utf-16be',
      confidence: 'bom',
      bomLength: 2,
      candidates: ['utf-16be'],
      note: 'BOM UTF-16 BE',
    }
  }

  const utf16 = detectUtf16ByNulParity(head)
  if (utf16) return utf16

  if (isValidUtf8(head)) {
    return {
      label: 'utf-8',
      confidence: 'high',
      bomLength: 0,
      candidates: ['utf-8', 'windows-1250', 'iso-8859-2'],
      note: 'valid-utf8',
    }
  }

  const cp = countBytes(head, CP1250_CZECH_BYTES)
  const l2 = countBytes(head, LATIN2_CZECH_BYTES)
  if (cp === 0 && l2 === 0) {
    return {
      label: 'windows-1250',
      confidence: 'low',
      bomLength: 0,
      candidates: ['windows-1250', 'iso-8859-2', 'utf-8'],
      note: 'invalid-utf8-default-cp1250',
    }
  }
  if (cp >= l2) {
    return {
      label: 'windows-1250',
      confidence: cp > l2 + 2 ? 'medium' : 'low',
      bomLength: 0,
      candidates: ['windows-1250', 'iso-8859-2', 'utf-8'],
      note: 'cp1250-heuristic',
    }
  }
  return {
    label: 'iso-8859-2',
    confidence: l2 > cp + 2 ? 'medium' : 'low',
    bomLength: 0,
    candidates: ['iso-8859-2', 'windows-1250', 'utf-8'],
    note: 'iso-8859-2-heuristic',
  }
}

function detectUtf16ByNulParity(head: Uint8Array): TextEncodingDetection | null {
  const n = Math.min(head.byteLength, 4096)
  if (n < 4) return null
  let evenNul = 0
  let oddNul = 0
  let printableEven = 0
  let printableOdd = 0
  for (let i = 0; i < n; i++) {
    const b = head[i]!
    if (b === 0) {
      if ((i & 1) === 0) evenNul++
      else oddNul++
    } else if (b >= 0x20 && b < 0x7f) {
      if ((i & 1) === 0) printableEven++
      else printableOdd++
    }
  }
  const nulTotal = evenNul + oddNul
  if (nulTotal < n * 0.15) return null
  // UTF-16 LE ASCII: NUL on odd indexes; BE: NUL on even indexes.
  if (oddNul > evenNul * 2 && printableEven > printableOdd) {
    return {
      label: 'utf-16le',
      confidence: 'high',
      bomLength: 0,
      candidates: ['utf-16le', 'utf-16be'],
      note: 'utf16-nul-parity-le',
    }
  }
  if (evenNul > oddNul * 2 && printableOdd > printableEven) {
    return {
      label: 'utf-16be',
      confidence: 'high',
      bomLength: 0,
      candidates: ['utf-16be', 'utf-16le'],
      note: 'utf16-nul-parity-be',
    }
  }
  return null
}

function countBytes(sample: Uint8Array, set: ReadonlySet<number>): number {
  let n = 0
  const lim = Math.min(sample.byteLength, 8192)
  for (let i = 0; i < lim; i++) {
    if (set.has(sample[i]!)) n++
  }
  return n
}

/** Structural UTF-8 validation (no decoder replacement). */
export function isValidUtf8(bytes: Uint8Array): boolean {
  let i = 0
  const n = bytes.byteLength
  while (i < n) {
    const b = bytes[i]!
    if (b <= 0x7f) {
      i++
      continue
    }
    let need = 0
    if ((b & 0xe0) === 0xc0) need = 1
    else if ((b & 0xf0) === 0xe0) need = 2
    else if ((b & 0xf8) === 0xf0) need = 3
    else return false
    if (i + need >= n) return false
    if (b === 0xc0 || b === 0xc1 || b >= 0xf5) return false
    for (let k = 1; k <= need; k++) {
      if ((bytes[i + k]! & 0xc0) !== 0x80) return false
    }
    i += need + 1
  }
  return true
}

export function createTextDecoder(
  label: TextEncodingLabel,
  options?: { readonly fatal?: boolean },
): TextDecoder {
  return new TextDecoder(label, { fatal: options?.fatal ?? false })
}

/**
 * Decode a complete buffer with optional BOM skip from detection.
 * Reports replacement characters via `hadReplacement`.
 */
export function decodeTextBuffer(
  bytes: Uint8Array,
  label: TextEncodingLabel,
  bomLength = 0,
): { readonly text: string; readonly hadReplacement: boolean } {
  const slice = bomLength > 0 ? bytes.subarray(bomLength) : bytes
  const text = createTextDecoder(label, { fatal: false }).decode(slice)
  return { text, hadReplacement: text.includes('\uFFFD') }
}

/** Windows EVTX magic `ElfFile\0`. */
export function looksLikeEvtx(head: Uint8Array): boolean {
  if (head.byteLength < 7) return false
  return (
    head[0] === 0x45
    && head[1] === 0x6c
    && head[2] === 0x66
    && head[3] === 0x46
    && head[4] === 0x69
    && head[5] === 0x6c
    && head[6] === 0x65
  )
}

/** systemd journal binary header starts with `LPKSHHRH`. */
export function looksLikeSystemdJournal(head: Uint8Array): boolean {
  if (head.byteLength < 8) return false
  return (
    head[0] === 0x4c
    && head[1] === 0x50
    && head[2] === 0x4b
    && head[3] === 0x53
    && head[4] === 0x48
    && head[5] === 0x48
    && head[6] === 0x52
    && head[7] === 0x48
  )
}

/** ETL / Windows Trace Event often starts with contiguous binary; use `.etl` + high NUL density. */
export function looksLikeEtlByName(fileName: string | undefined): boolean {
  return !!fileName && /\.etl$/i.test(fileName)
}

export function labelDisplayName(label: TextEncodingLabel): string {
  switch (label) {
    case 'utf-8':
      return 'UTF-8'
    case 'windows-1250':
      return 'Windows-1250'
    case 'iso-8859-2':
      return 'ISO-8859-2'
    case 'utf-16le':
      return 'UTF-16 LE'
    case 'utf-16be':
      return 'UTF-16 BE'
  }
}
