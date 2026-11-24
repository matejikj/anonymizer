/**
 * Deterministic entropy expansion for TEST MODE session seeds.
 * Stable across browser/Node — not a cryptographic KDF.
 */

const ENTROPY_BYTES = 4096

/** Expand an opaque seed string into a fixed-length entropy buffer (FNV-1a stream). */
export function expandSeedToEntropy(seed: string, byteLength = ENTROPY_BYTES): Uint8Array {
  const out = new Uint8Array(byteLength)
  let h = 2166136261 >>> 0
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i)
    h = Math.imul(h, 16777619) >>> 0
  }
  for (let i = 0; i < out.length; i++) {
    h ^= i + 1
    h = Math.imul(h, 16777619) >>> 0
    h ^= h << 13
    h ^= h >>> 17
    h ^= h << 5
    out[i] = h & 0xff
  }
  return out
}

/** Fresh CSPRNG (or Math.random fallback) entropy for production sessions. */
export function freshEntropy(byteLength = ENTROPY_BYTES): Uint8Array {
  const out = new Uint8Array(byteLength)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(out as Uint8Array<ArrayBuffer>)
  } else {
    for (let i = 0; i < out.length; i++) {
      out[i] = (Math.random() * 256) | 0
    }
  }
  return out
}
