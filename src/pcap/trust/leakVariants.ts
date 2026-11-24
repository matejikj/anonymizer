/**
 * T65 — encoding variants of discovery originals for leak scanning.
 * Never logs or returns the original as a "finding" — only needle bytes for matching.
 */

export type LeakNeedleKind = 'binary' | 'text'

export interface LeakNeedle {
  readonly id: number
  /** Entity / protocol category code — mapped to LeakCategory by the scanner. */
  readonly category: string
  readonly kind: LeakNeedleKind
  readonly bytes: Uint8Array
  /** Source entity packet number (for aggregates) — not the hit location. */
  readonly sourcePacketNumber: number
}

const MAX_TEXT_NEEDLE = 256
const MIN_TEXT_NEEDLE = 3
const MIN_HEX_ASCII = 8

function latin1Bytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length)
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff
  return out
}

function utf16Bytes(text: string, littleEndian: boolean): Uint8Array {
  const out = new Uint8Array(text.length * 2)
  const view = new DataView(out.buffer)
  for (let i = 0; i < text.length; i++) {
    view.setUint16(i * 2, text.charCodeAt(i), littleEndian)
  }
  return out
}

function parseIpv4(text: string): Uint8Array | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text.trim())
  if (!m) return null
  const parts = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])]
  if (parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null
  return Uint8Array.from(parts)
}

function parseIpv6(text: string): Uint8Array | null {
  const raw = text.trim()
  if (!raw.includes(':')) return null
  // Expand :: once.
  const lower = raw.toLowerCase()
  if (lower === '::') return new Uint8Array(16)
  const sides = lower.split('::')
  if (sides.length > 2) return null
  const head = sides[0] ? sides[0].split(':').filter(Boolean) : []
  const tail = sides.length === 2 && sides[1] ? sides[1].split(':').filter(Boolean) : []
  if (sides.length === 1) {
    if (head.length !== 8) return null
  } else if (head.length + tail.length > 7) {
    return null
  }
  const groups: number[] = []
  for (const g of head) {
    const n = Number.parseInt(g, 16)
    if (!Number.isFinite(n) || n < 0 || n > 0xffff) return null
    groups.push(n)
  }
  const missing = 8 - head.length - tail.length
  for (let i = 0; i < missing; i++) groups.push(0)
  for (const g of tail) {
    const n = Number.parseInt(g, 16)
    if (!Number.isFinite(n) || n < 0 || n > 0xffff) return null
    groups.push(n)
  }
  if (groups.length !== 8) return null
  const out = new Uint8Array(16)
  for (let i = 0; i < 8; i++) {
    out[i * 2] = (groups[i]! >> 8) & 0xff
    out[i * 2 + 1] = groups[i]! & 0xff
  }
  return out
}

function parseMac(text: string): Uint8Array | null {
  const cleaned = text.trim().toLowerCase()
  const m = /^([0-9a-f]{2})([:\-]?([0-9a-f]{2})){5}$/.exec(cleaned.replace(/\./g, ''))
  if (!m && !/^([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}$/.test(cleaned)) {
    const compact = cleaned.replace(/[:\-.]/g, '')
    if (!/^[0-9a-f]{12}$/.test(compact)) return null
    const out = new Uint8Array(6)
    for (let i = 0; i < 6; i++) out[i] = Number.parseInt(compact.slice(i * 2, i * 2 + 2), 16)
    return out
  }
  const compact = cleaned.replace(/[:\-.]/g, '')
  if (!/^[0-9a-f]{12}$/.test(compact)) return null
  const out = new Uint8Array(6)
  for (let i = 0; i < 6; i++) out[i] = Number.parseInt(compact.slice(i * 2, i * 2 + 2), 16)
  return out
}

function pushUnique(list: LeakNeedle[], seen: Set<string>, needle: Omit<LeakNeedle, 'id'>): void {
  if (needle.bytes.length === 0) return
  if (needle.kind === 'text' && needle.bytes.length < MIN_TEXT_NEEDLE) return
  if (needle.kind === 'binary' && needle.bytes.length < 4) return
  const key = `${needle.kind}:${needle.category}:${needle.bytes.length}:${[...needle.bytes].join(',')}`
  if (seen.has(key)) return
  seen.add(key)
  list.push({ ...needle, id: list.length })
}

function base64Ascii(bytes: Uint8Array): string {
  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  let out = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!
    const b = i + 1 < bytes.length ? bytes[i + 1]! : 0
    const c = i + 2 < bytes.length ? bytes[i + 2]! : 0
    const triple = (a << 16) | (b << 8) | c
    out += chars[(triple >> 18) & 63]
    out += chars[(triple >> 12) & 63]
    out += i + 1 < bytes.length ? chars[(triple >> 6) & 63] : '='
    out += i + 2 < bytes.length ? chars[triple & 63] : '='
  }
  return out
}

function urlEncodeLatin1(text: string): string {
  let out = ''
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i) & 0xff
    if (
      (c >= 0x30 && c <= 0x39)
      || (c >= 0x41 && c <= 0x5a)
      || (c >= 0x61 && c <= 0x7a)
      || c === 0x2d
      || c === 0x2e
      || c === 0x5f
      || c === 0x7e
    ) {
      out += String.fromCharCode(c)
    } else {
      out += `%${c.toString(16).toUpperCase().padStart(2, '0')}`
    }
  }
  return out
}

/**
 * Expand discovery originals into scan needles (capped by caller via slice).
 * EBCDIC omitted unless a future caller proves EBCDIC framing in the capture.
 */
export function buildLeakNeedles(
  originals: readonly { readonly category: string; readonly value: string; readonly packetNumber: number }[],
): readonly LeakNeedle[] {
  const out: LeakNeedle[] = []
  const seen = new Set<string>()

  for (const orig of originals) {
    const value = orig.value.trim()
    if (value.length < MIN_TEXT_NEEDLE) continue
    if (/^x+$/i.test(value) || value === '::' || /^0+(\.0+){3}$/.test(value)) continue
    const category = orig.category
    const clipped = value.length > MAX_TEXT_NEEDLE ? value.slice(0, MAX_TEXT_NEEDLE) : value

    // Text / case variants
    pushUnique(out, seen, {
      category,
      kind: 'text',
      bytes: latin1Bytes(clipped),
      sourcePacketNumber: orig.packetNumber,
    })
    const lower = clipped.toLowerCase()
    if (lower !== clipped) {
      pushUnique(out, seen, {
        category,
        kind: 'text',
        bytes: latin1Bytes(lower),
        sourcePacketNumber: orig.packetNumber,
      })
    }
    const upper = clipped.toUpperCase()
    if (upper !== clipped && upper !== lower) {
      pushUnique(out, seen, {
        category,
        kind: 'text',
        bytes: latin1Bytes(upper),
        sourcePacketNumber: orig.packetNumber,
      })
    }

    // Binary wire forms for addresses
    const v4 = parseIpv4(clipped)
    if (v4) {
      pushUnique(out, seen, {
        category: 'ipv4',
        kind: 'binary',
        bytes: v4,
        sourcePacketNumber: orig.packetNumber,
      })
    }
    const v6 = parseIpv6(clipped)
    if (v6) {
      pushUnique(out, seen, {
        category: 'ipv6',
        kind: 'binary',
        bytes: v6,
        sourcePacketNumber: orig.packetNumber,
      })
    }
    const mac = parseMac(clipped)
    if (mac) {
      pushUnique(out, seen, {
        category: 'mac',
        kind: 'binary',
        bytes: mac,
        sourcePacketNumber: orig.packetNumber,
      })
    }

    // Hex / base64 / URL of the latin1 payload
    const raw = latin1Bytes(clipped)
    if (raw.length >= 4) {
      const hex = [...raw].map((b) => b.toString(16).padStart(2, '0')).join('')
      if (hex.length >= MIN_HEX_ASCII) {
        pushUnique(out, seen, {
          category,
          kind: 'text',
          bytes: latin1Bytes(hex),
          sourcePacketNumber: orig.packetNumber,
        })
        pushUnique(out, seen, {
          category,
          kind: 'text',
          bytes: latin1Bytes(hex.toUpperCase()),
          sourcePacketNumber: orig.packetNumber,
        })
        if (raw.length <= 32) {
          pushUnique(out, seen, {
            category,
            kind: 'text',
            bytes: latin1Bytes([...raw].map((b) => b.toString(16).padStart(2, '0')).join(':')),
            sourcePacketNumber: orig.packetNumber,
          })
          pushUnique(out, seen, {
            category,
            kind: 'text',
            bytes: latin1Bytes([...raw].map((b) => b.toString(16).padStart(2, '0')).join('-')),
            sourcePacketNumber: orig.packetNumber,
          })
        }
      }
      const b64 = base64Ascii(raw)
      if (b64.length >= 8) {
        pushUnique(out, seen, {
          category,
          kind: 'text',
          bytes: latin1Bytes(b64),
          sourcePacketNumber: orig.packetNumber,
        })
      }
      const enc = urlEncodeLatin1(clipped)
      if (enc !== clipped && enc.length >= MIN_TEXT_NEEDLE) {
        pushUnique(out, seen, {
          category,
          kind: 'text',
          bytes: latin1Bytes(enc),
          sourcePacketNumber: orig.packetNumber,
        })
      }
    }

    // UTF-16LE / BE text encodings
    if (clipped.length >= 2 && clipped.length <= 64) {
      pushUnique(out, seen, {
        category,
        kind: 'text',
        bytes: utf16Bytes(clipped, true),
        sourcePacketNumber: orig.packetNumber,
      })
      pushUnique(out, seen, {
        category,
        kind: 'text',
        bytes: utf16Bytes(clipped, false),
        sourcePacketNumber: orig.packetNumber,
      })
    }
  }

  return out
}
