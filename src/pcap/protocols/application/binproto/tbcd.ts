/**
 * T16 — BCD / TBCD codecs + length-preserving digit remapping for phone/IMSI/IMEI.
 */

export type NibbleOrder = 'low-first' | 'high-first'

export interface TbcdCodecOptions {
  readonly nibbleOrder: NibbleOrder
  /** Filler nibble for odd digit counts (typically 0xF). */
  readonly fillerNibble: number
  /** Extra alphabet mapped to nibbles 0xA–0xE (e.g. '*','#','a','b','c'). */
  readonly alphabet?: Readonly<Record<string, number>>
}

export const TBCD_GSM: TbcdCodecOptions = {
  nibbleOrder: 'low-first',
  fillerNibble: 0x0f,
  alphabet: { '*': 0x0a, '#': 0x0b, a: 0x0c, b: 0x0d, c: 0x0e },
}

export const BCD_HIGH_FIRST: TbcdCodecOptions = {
  nibbleOrder: 'high-first',
  fillerNibble: 0x0f,
}

const DIGIT_FROM_NIBBLE = '0123456789*#abc'

function nibbleToChar(n: number, alphabet: TbcdCodecOptions['alphabet']): string | null {
  if (n <= 9) return String(n)
  if (alphabet) {
    for (const [ch, v] of Object.entries(alphabet)) {
      if (v === n) return ch
    }
  }
  if (n >= 0x0a && n <= 0x0e) return DIGIT_FROM_NIBBLE[n] ?? null
  return null
}

function charToNibble(ch: string, opts: TbcdCodecOptions): number | null {
  if (ch >= '0' && ch <= '9') return ch.charCodeAt(0) - 48
  const lower = ch.toLowerCase()
  if (opts.alphabet && lower in opts.alphabet) return opts.alphabet[lower]!
  return null
}

/** Decode TBCD/BCD bytes to digit string (stops at filler). */
export function decodeTbcd(
  bytes: Uint8Array,
  options: TbcdCodecOptions = TBCD_GSM,
): string | null {
  if (bytes.length === 0) return null
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!
    const low = b & 0x0f
    const high = (b >> 4) & 0x0f
    const first = options.nibbleOrder === 'low-first' ? low : high
    const second = options.nibbleOrder === 'low-first' ? high : low
    if (first === options.fillerNibble) break
    const c1 = nibbleToChar(first, options.alphabet)
    if (c1 === null) return null
    out += c1
    if (second === options.fillerNibble) break
    const c2 = nibbleToChar(second, options.alphabet)
    if (c2 === null) return null
    out += c2
  }
  return out.length > 0 ? out : null
}

/** Encode digit string into fixed byteLength TBCD (pad with filler). */
export function encodeTbcd(
  digits: string,
  byteLength: number,
  options: TbcdCodecOptions = TBCD_GSM,
): Uint8Array | null {
  if (byteLength <= 0 || byteLength > 32) return null
  const maxDigits = byteLength * 2
  if (digits.length === 0 || digits.length > maxDigits) return null
  const out = new Uint8Array(byteLength)
  out.fill(options.fillerNibble === 0x0f ? 0xff : (options.fillerNibble << 4) | options.fillerNibble)
  let digi = 0
  for (let i = 0; i < byteLength && digi < digits.length; i++) {
    const n1 = charToNibble(digits[digi++]!, options)
    if (n1 === null) return null
    let n2 = options.fillerNibble
    if (digi < digits.length) {
      const parsed = charToNibble(digits[digi++]!, options)
      if (parsed === null) return null
      n2 = parsed
    }
    out[i] = options.nibbleOrder === 'low-first'
      ? ((n2 << 4) | n1) & 0xff
      : ((n1 << 4) | n2) & 0xff
  }
  return out
}

/**
 * Remap TBCD digits through an already-resolved digit alias of the same length.
 * Preserves nibble order and filler parity.
 */
export function remapTbcdBytes(
  original: Uint8Array,
  mappedDigits: string,
  options: TbcdCodecOptions = TBCD_GSM,
): Uint8Array | null {
  const decoded = decodeTbcd(original, options)
  if (!decoded || mappedDigits.length !== decoded.length) return null
  return encodeTbcd(mappedDigits, original.length, options)
}

/**
 * Authoritative separator when PLMN (MCC+MNC) is known from protocol context.
 * Must never appear in wire digit strings; mirrors SDP session-id author scope.
 */
export const IMSI_PLMN_SCOPE_SEP = '\x1f'

/** IMSI: 5–15 digits; no PLMN split without explicit context. */
export function normalizeImsiDigits(raw: string): string | null {
  const sep = raw.indexOf(IMSI_PLMN_SCOPE_SEP)
  if (sep >= 0) {
    const plmn = raw.slice(0, sep).replace(/\D/g, '')
    const msin = raw.slice(sep + 1).replace(/\D/g, '')
    if (plmn.length < 5 || plmn.length > 6) return null // MCC(3)+MNC(2|3)
    if (msin.length === 0) return null
    if (plmn.length + msin.length > 15) return null
    return `${plmn}${IMSI_PLMN_SCOPE_SEP}${msin}`
  }
  const digits = raw.replace(/\D/g, '')
  if (digits.length < 5 || digits.length > 15) return null
  return digits
}

/** Digits as they appear on the wire (PLMN scope separator removed). */
export function imsiWireDigits(canonical: string): string {
  return canonical.includes(IMSI_PLMN_SCOPE_SEP)
    ? canonical.split(IMSI_PLMN_SCOPE_SEP).join('')
    : canonical
}

/**
 * Build a PLMN-scoped IMSI canonical when MNC length is known from context.
 * Without a documented MNC length, callers must use plain digit strings.
 */
export function scopeImsiWithPlmn(digits: string, mncLength: 2 | 3): string | null {
  const d = digits.replace(/\D/g, '')
  if (d.length < 5 || d.length > 15) return null
  const plmnLen = 3 + mncLength
  if (d.length < plmnLen) return null
  return `${d.slice(0, plmnLen)}${IMSI_PLMN_SCOPE_SEP}${d.slice(plmnLen)}`
}

/** IMEI 14–15 digits; IMEISV 16 digits. */
export function normalizeImeiDigits(raw: string): string | null {
  const digits = raw.replace(/\D/g, '')
  if (digits.length < 14 || digits.length > 16) return null
  return digits
}

/**
 * GSMA IMEI Luhn check digit over the first 14 digits (doubling from the right).
 * Not used for IMEISV (16 digits) or bare 14-digit bodies without check digit.
 */
export function imeiLuhnCheckDigit(body14: string): number | null {
  if (!/^\d{14}$/.test(body14)) return null
  let sum = 0
  for (let i = 0; i < 14; i++) {
    let n = body14.charCodeAt(i)! - 48
    // From the right: positions 0,2,4… are doubled → odd indices from the left.
    if (i % 2 === 1) {
      n *= 2
      if (n > 9) n -= 9
    }
    sum += n
  }
  return (10 - (sum % 10)) % 10
}

/** True when a 15-digit IMEI has a valid Luhn check digit. */
export function isValidImeiLuhn(imei15: string): boolean {
  if (!/^\d{15}$/.test(imei15)) return false
  const expected = imeiLuhnCheckDigit(imei15.slice(0, 14))
  return expected !== null && expected === Number(imei15[14])
}

/**
 * Build a length-stable IMEI/IMEISV alias: random body + Luhn for 15-digit IMEI;
 * 14-digit bodies and 16-digit IMEISV stay pure length-stable digits.
 */
export function finalizeImeiAliasDigits(candidateBody: string, targetLength: number): string | null {
  if (targetLength === 15) {
    const body =
      candidateBody.length === 14
        ? candidateBody
        : candidateBody.length >= 14
          ? candidateBody.slice(0, 14)
          : null
    if (!body || !/^\d{14}$/.test(body)) return null
    const check = imeiLuhnCheckDigit(body)
    if (check === null) return null
    return `${body}${check}`
  }
  if (targetLength === 14 || targetLength === 16) {
    if (!/^\d+$/.test(candidateBody) || candidateBody.length !== targetLength) return null
    return candidateBody
  }
  return null
}
