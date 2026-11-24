/**
 * Topology-preserving host-bit derivation (integer mix — not AES Crypto-PAn).
 *
 * Given a session-random key and an original address, derives the low
 * `bitCount` bits of a first-choice candidate such that two originals that
 * share a prefix often share the corresponding bits in the candidate. The
 * caller runs the candidate through exclusive allocation inside a fixed /24
 * bucket in the target /16 (see SessionMapping._mapIpv4), so collisions
 * keep same-/24 prefix↔host coherence without claiming Crypto-PAn secrecy.
 *
 * Classic Crypto-PAn (Xu/Fan/Ammar/Moore 2002) uses AES-128 as the
 * per-bit-position PRF. This engine stays fully synchronous (up to
 * MAX_ENTITY_CARDINALITY calls per export) and WebCrypto AES is async-only,
 * so this uses a fast integer-mixing PRF instead. No cryptographic secrecy is
 * claimed — same trust boundary as FNV/xorshift mask fill.
 */

export interface PrefixPreservingKey {
  readonly words: readonly [number, number, number, number]
}

export function createPrefixPreservingKey(nextRandomU32: () => number): PrefixPreservingKey {
  return { words: [nextRandomU32(), nextRandomU32(), nextRandomU32(), nextRandomU32()] }
}

/** 32-bit avalanche mix (murmur3 finalizer), used as the per-position PRF. */
function mix32(a: number, b: number): number {
  let h = (a ^ b) >>> 0
  h = Math.imul(h ^ (h >>> 16), 0x85ebca6b) >>> 0
  h = Math.imul(h ^ (h >>> 13), 0xc2b2ae35) >>> 0
  h ^= h >>> 16
  return h >>> 0
}

/**
 * Derives the low `bitCount` bits of a `totalBits`-wide value.
 * `readBit(i)` returns bit `i` of the original value, MSB-first (i=0 is the
 * top bit of the conceptual `totalBits`-wide value).
 */
function derivePreservedBits(
  key: PrefixPreservingKey,
  totalBits: number,
  bitCount: number,
  readBit: (i: number) => number,
): number {
  const fixedBits = totalBits - bitCount
  // Rolling accumulation of the original's prefix bits seen so far, as a
  // 64-bit value split across two 32-bit halves (prefixes longer than 32
  // bits still need to differentiate on their earlier bits).
  let prefixLo = 0
  let prefixHi = 0
  const advance = (bit: number) => {
    prefixHi = ((prefixHi << 1) | (prefixLo >>> 31)) >>> 0
    prefixLo = ((prefixLo << 1) | bit) >>> 0
  }
  for (let i = 0; i < fixedBits; i++) advance(readBit(i))

  let out = 0
  for (let i = 0; i < bitCount; i++) {
    const globalPos = fixedBits + i
    const bit = readBit(globalPos)
    const seed = mix32(
      mix32(key.words[globalPos & 3]!, key.words[(globalPos + 1) & 3]! ^ Math.imul(globalPos, 0x9e3779b1)),
      mix32(prefixLo, prefixHi ^ key.words[(globalPos + 2) & 3]!),
    )
    const pseudoBit = seed & 1
    out = ((out << 1) | (pseudoBit ^ bit)) >>> 0
    advance(bit)
  }
  return out >>> 0
}

/** Derives the low `hostBitCount` bits of a 32-bit (IPv4) address. */
export function derivePreservedIpv4HostBits(
  key: PrefixPreservingKey,
  address32: number,
  hostBitCount: number,
): number {
  const a = address32 >>> 0
  return derivePreservedBits(key, 32, hostBitCount, (i) => (a >>> (31 - i)) & 1)
}

/** Derives the low `hostBitCount` bits of a 128-bit (IPv6) address, given as 4 big-endian 32-bit words. */
export function derivePreservedIpv6HostBits(
  key: PrefixPreservingKey,
  addressWords: readonly [number, number, number, number],
  hostBitCount: number,
): number {
  const readBit = (i: number): number => {
    const w = addressWords[i >>> 5]! >>> 0
    return (w >>> (31 - (i & 31))) & 1
  }
  return derivePreservedBits(key, 128, hostBitCount, readBit)
}
