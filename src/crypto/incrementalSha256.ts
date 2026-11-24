/**
 * Incremental SHA-256 (FIPS 180-4). Chunk boundaries do not affect the digest.
 * Used for streaming original/anonymized hashing without a full-file ArrayBuffer.
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n))
}

export class IncrementalSha256 {
  private h0 = 0x6a09e667
  private h1 = 0xbb67ae85
  private h2 = 0x3c6ef372
  private h3 = 0xa54ff53a
  private h4 = 0x510e527f
  private h5 = 0x9b05688c
  private h6 = 0x1f83d9ab
  private h7 = 0x5be0cd19
  private readonly block = new Uint8Array(64)
  private blockOffset = 0
  private bytesHashed = 0
  private finalized = false
  private readonly w = new Uint32Array(64)

  update(chunk: Uint8Array): this {
    if (this.finalized) {
      throw new Error('SHA-256 hasher already finalized')
    }
    if (chunk.byteLength === 0) return this
    this.bytesHashed += chunk.byteLength
    let offset = 0
    while (offset < chunk.byteLength) {
      const take = Math.min(64 - this.blockOffset, chunk.byteLength - offset)
      this.block.set(chunk.subarray(offset, offset + take), this.blockOffset)
      this.blockOffset += take
      offset += take
      if (this.blockOffset === 64) {
        this.compress(this.block)
        this.blockOffset = 0
      }
    }
    return this
  }

  digest(): Uint8Array {
    if (this.finalized) {
      throw new Error('SHA-256 hasher already finalized')
    }
    this.finalized = true
    this.block[this.blockOffset] = 0x80
    for (let i = this.blockOffset + 1; i < 64; i++) this.block[i] = 0
    if (this.blockOffset >= 56) {
      this.compress(this.block)
      this.block.fill(0)
    }
    const bitLenHi = Math.floor(this.bytesHashed / 0x20000000)
    const bitLenLo = (this.bytesHashed << 3) >>> 0
    this.block[56] = (bitLenHi >>> 24) & 0xff
    this.block[57] = (bitLenHi >>> 16) & 0xff
    this.block[58] = (bitLenHi >>> 8) & 0xff
    this.block[59] = bitLenHi & 0xff
    this.block[60] = (bitLenLo >>> 24) & 0xff
    this.block[61] = (bitLenLo >>> 16) & 0xff
    this.block[62] = (bitLenLo >>> 8) & 0xff
    this.block[63] = bitLenLo & 0xff
    this.compress(this.block)
    this.block.fill(0)

    const out = new Uint8Array(32)
    const words = [this.h0, this.h1, this.h2, this.h3, this.h4, this.h5, this.h6, this.h7]
    for (let i = 0; i < 8; i++) {
      const w = words[i]!
      out[i * 4] = (w >>> 24) & 0xff
      out[i * 4 + 1] = (w >>> 16) & 0xff
      out[i * 4 + 2] = (w >>> 8) & 0xff
      out[i * 4 + 3] = w & 0xff
    }
    return out
  }

  private compress(block: Uint8Array): void {
    const w = this.w
    for (let i = 0; i < 16; i++) {
      const j = i * 4
      w[i] =
        ((block[j]! << 24) | (block[j + 1]! << 16) | (block[j + 2]! << 8) | block[j + 3]!) >>> 0
    }
    for (let i = 16; i < 64; i++) {
      const w15 = w[i - 15]!
      const w2 = w[i - 2]!
      const s0 = (rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3)) >>> 0
      const s1 = (rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10)) >>> 0
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0
    }

    let a = this.h0
    let b = this.h1
    let c = this.h2
    let d = this.h3
    let e = this.h4
    let f = this.h5
    let g = this.h6
    let h = this.h7

    for (let i = 0; i < 64; i++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0
      const ch = ((e & f) ^ (~e & g)) >>> 0
      const temp1 = (h + S1 + ch + K[i]! + w[i]!) >>> 0
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0
      const temp2 = (S0 + maj) >>> 0
      h = g
      g = f
      f = e
      e = (d + temp1) >>> 0
      d = c
      c = b
      b = a
      a = (temp1 + temp2) >>> 0
    }

    this.h0 = (this.h0 + a) >>> 0
    this.h1 = (this.h1 + b) >>> 0
    this.h2 = (this.h2 + c) >>> 0
    this.h3 = (this.h3 + d) >>> 0
    this.h4 = (this.h4 + e) >>> 0
    this.h5 = (this.h5 + f) >>> 0
    this.h6 = (this.h6 + g) >>> 0
    this.h7 = (this.h7 + h) >>> 0
  }
}

export function sha256(data: Uint8Array): Uint8Array {
  return new IncrementalSha256().update(data).digest()
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false
  let diff = 0
  for (let i = 0; i < a.byteLength; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, '').toLowerCase()
  if (clean.length % 2 !== 0) {
    throw new Error('hex length must be even')
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.byteLength; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}
