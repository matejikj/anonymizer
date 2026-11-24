/**
 * Modular SDP o= session-version shift (T01).
 *
 * session-version is not a MappingAuthority identity. At plan-build time the deferred
 * patch derives Δ from the already-resolved session-id alias so preview === export.
 *
 * L == L_id:  Δ = (alias(session-id) − session-id) mod 10^L
 * otherwise:  Δ = deterministic non-zero hash(session-id alias, L) mod 10^L
 * version' = (version + Δ) mod 10^L, left-padded to width L
 */

/** Apply modular shift; inputs must be digit strings of length ≥ 1. */
export function shiftSessionVersion(
  versionDigits: string,
  sessionIdDigits: string,
  sessionIdAlias: string,
): string {
  const L = versionDigits.length
  if (L === 0 || !/^\d+$/.test(versionDigits) || !/^\d+$/.test(sessionIdDigits)) {
    return '0'.repeat(Math.max(0, L))
  }
  if (!/^\d+$/.test(sessionIdAlias) || sessionIdAlias.length !== sessionIdDigits.length) {
    // Session-id mapping failed — mask version (T04 will add field fallback).
    return '0'.repeat(L)
  }

  const mod = 10n ** BigInt(L)
  const version = BigInt(versionDigits)
  const LId = sessionIdDigits.length
  let delta: bigint
  if (L === LId) {
    const id = BigInt(sessionIdDigits)
    const alias = BigInt(sessionIdAlias)
    delta = ((alias - id) % mod + mod) % mod
  } else {
    delta = independentVersionDelta(sessionIdAlias, L)
  }
  // Independent offset must never be zero (would leave the protected value unchanged).
  if (delta === 0n) delta = 1n

  const shifted = (version + delta) % mod
  return shifted.toString().padStart(L, '0')
}

/**
 * Deterministic non-zero Δ for short/mismatched version width.
 * Derived from the session-id alias (available after resolve) so it is stable across
 * preview and export without storing per-session CSPRNG state in the plan snapshot.
 */
export function independentVersionDelta(sessionIdAlias: string, versionWidth: number): bigint {
  const mod = 10n ** BigInt(versionWidth)
  if (mod <= 1n) return 0n
  // FNV-1a 64-bit over "alias:L"
  let hash = 0xcbf29ce484222325n
  const key = `${sessionIdAlias}:${versionWidth}`
  for (let i = 0; i < key.length; i++) {
    hash ^= BigInt(key.charCodeAt(i) & 0xff)
    hash = (hash * 0x100000001b3n) & 0xffffffffffffffffn
  }
  let delta = hash % mod
  if (delta === 0n) delta = 1n
  return delta
}
