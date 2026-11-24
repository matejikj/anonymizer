/**
 * Sync SHA-1 (FIPS 180-4) for WebSocket Sec-WebSocket-Accept (RFC 6455).
 * Not for password hashing — Accept binding only.
 */

function rol(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0
}

export function sha1(data: Uint8Array): Uint8Array {
  let h0 = 0x67452301
  let h1 = 0xefcdab89
  let h2 = 0x98badcfe
  let h3 = 0x10325476
  let h4 = 0xc3d2e1f0

  const bitLen = BigInt(data.length) * 8n
  const withOne = data.length + 1
  const padLen = (56 - (withOne % 64) + 64) % 64
  const total = withOne + padLen + 8
  const msg = new Uint8Array(total)
  msg.set(data)
  msg[data.length] = 0x80
  const view = new DataView(msg.buffer)
  view.setUint32(total - 8, Number(bitLen >> 32n), false)
  view.setUint32(total - 4, Number(bitLen & 0xffff_ffffn), false)

  const w = new Uint32Array(80)
  for (let i = 0; i < total; i += 64) {
    for (let j = 0; j < 16; j++) {
      w[j] = view.getUint32(i + j * 4, false)
    }
    for (let j = 16; j < 80; j++) {
      w[j] = rol(w[j - 3]! ^ w[j - 8]! ^ w[j - 14]! ^ w[j - 16]!, 1)
    }
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4
    for (let j = 0; j < 80; j++) {
      let f: number
      let k: number
      if (j < 20) {
        f = (b & c) | (~b & d)
        k = 0x5a827999
      } else if (j < 40) {
        f = b ^ c ^ d
        k = 0x6ed9eba1
      } else if (j < 60) {
        f = (b & c) | (b & d) | (c & d)
        k = 0x8f1bbcdc
      } else {
        f = b ^ c ^ d
        k = 0xca62c1d6
      }
      const temp = (rol(a, 5) + f + e + k + w[j]!) >>> 0
      e = d
      d = c
      c = rol(b, 30)
      b = a
      a = temp
    }
    h0 = (h0 + a) >>> 0
    h1 = (h1 + b) >>> 0
    h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0
  }

  const out = new Uint8Array(20)
  const ov = new DataView(out.buffer)
  ov.setUint32(0, h0, false)
  ov.setUint32(4, h1, false)
  ov.setUint32(8, h2, false)
  ov.setUint32(12, h3, false)
  ov.setUint32(16, h4, false)
  return out
}

/** RFC 6455 §1.3 — Accept = base64(SHA1(key + GUID)). */
export const WEBSOCKET_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

export function webSocketAcceptFromKey(keyAscii: string): string {
  const enc = new TextEncoder()
  const digest = sha1(enc.encode(keyAscii + WEBSOCKET_GUID))
  return bytesToBase64(digest)
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
  return btoa(bin)
}
