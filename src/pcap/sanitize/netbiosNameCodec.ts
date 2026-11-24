/**
 * T18 — NetBIOS first-level encoding (RFC 1001/1002): 16 B name ↔ 32 A–P chars.
 */

const SPACE = 0x20

/** Decode 32-byte A–P label to 16 raw bytes; null if invalid. */
export function decodeNetbiosFirstLevel(encoded: Uint8Array): Uint8Array | null {
  if (encoded.length !== 32) return null
  const out = new Uint8Array(16)
  for (let i = 0; i < 16; i++) {
    const hi = encoded[i * 2]!
    const lo = encoded[i * 2 + 1]!
    if (hi < 0x41 || hi > 0x50 || lo < 0x41 || lo > 0x50) return null
    out[i] = ((hi - 0x41) << 4) | (lo - 0x41)
  }
  return out
}

/** Encode 16 raw bytes to 32-byte A–P label. */
export function encodeNetbiosFirstLevel(raw16: Uint8Array): Uint8Array | null {
  if (raw16.length !== 16) return null
  const out = new Uint8Array(32)
  for (let i = 0; i < 16; i++) {
    const b = raw16[i]!
    out[i * 2] = 0x41 + ((b >> 4) & 0x0f)
    out[i * 2 + 1] = 0x41 + (b & 0x0f)
  }
  return out
}

/**
 * Split 16 B NetBIOS name into hostname (≤15, space-padded) + suffix type byte.
 */
export function splitNetbiosName(raw16: Uint8Array): { host: string; suffix: number } | null {
  if (raw16.length !== 16) return null
  const suffix = raw16[15]!
  let end = 14
  while (end >= 0 && raw16[end] === SPACE) end--
  let host = ''
  for (let i = 0; i <= end; i++) {
    const c = raw16[i]!
    if (c < 0x20 || c > 0x7e) return null
    host += String.fromCharCode(c)
  }
  if (host.length === 0) return null
  return { host: host.toLowerCase(), suffix }
}

/** Build 16 B name from mapped host (≤15) + preserved suffix; space-pad. */
export function joinNetbiosName(host: string, suffix: number): Uint8Array | null {
  if (host.length === 0 || host.length > 15) return null
  const out = new Uint8Array(16)
  out.fill(SPACE)
  for (let i = 0; i < host.length; i++) {
    const c = host.charCodeAt(i)
    if (c < 0x20 || c > 0x7e) return null
    out[i] = c
  }
  out[15] = suffix & 0xff
  return out
}
