/**
 * T63.2 — deterministic canary byte patterns for field-policy conformance.
 * Never embed real sample identities; patterns are synthetic and unique per field path.
 */

import type { FieldCanaryKind } from '../kernel/fieldPolicy'

const FNV_OFFSET = 0x811c9dc5
const FNV_PRIME = 0x01000193

function fnv1a32(text: string): number {
  let h = FNV_OFFSET
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i) & 0xff
    h = Math.imul(h, FNV_PRIME)
  }
  return h >>> 0
}

function xorshift32(state: number): number {
  let x = state >>> 0
  x ^= x << 13
  x ^= x >>> 17
  x ^= x << 5
  return x >>> 0
}

/**
 * Build a length-preserving canary for `fieldPath`.
 * ASCII canaries stay in printable [0x41–0x5A]/[0x30–0x39] so text dissectors keep framing.
 */
export function buildFieldCanary(
  fieldPath: string,
  length: number,
  kind: FieldCanaryKind = 'binary',
): Uint8Array {
  if (length <= 0) return new Uint8Array(0)
  if (kind === 'none') return new Uint8Array(length)

  let state = fnv1a32(`t63-canary\0${fieldPath}\0${length}\0${kind}`)
  if (state === 0) state = 0x9e3779b9
  const out = new Uint8Array(length)

  if (kind === 'ascii') {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    for (let i = 0; i < length; i++) {
      state = xorshift32(state)
      out[i] = alphabet.charCodeAt(state % alphabet.length)!
    }
    return out
  }

  for (let i = 0; i < length; i++) {
    state = xorshift32(state)
    // Avoid 0x00 runs that some parsers treat as C-string terminators mid-field.
    out[i] = 0x40 + (state % 0xbf)
  }
  return out
}

/** True when `haystack` contains the exact canary byte sequence. */
export function bufferContainsCanary(haystack: Uint8Array, canary: Uint8Array): boolean {
  if (canary.length === 0 || canary.length > haystack.length) return false
  outer: for (let i = 0; i <= haystack.length - canary.length; i++) {
    for (let j = 0; j < canary.length; j++) {
      if (haystack[i + j] !== canary[j]) continue outer
    }
    return true
  }
  return false
}
