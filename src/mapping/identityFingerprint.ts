/**
 * Session-only keyed fingerprint for canonical identity (Stage 19).
 * Used after plaintext scrub — not reversible without session key.
 */

import type { IdentityCategory } from './identityCategories'
import { identityMappingKey } from './canonicalize'
import { correlationRegistryKeyFromParts } from './crossFormat/identityKey'

export const FINGERPRINT_VERSION = 1

/** Random session-only domain separation key — never persisted or exported. */
export type SessionFingerprintKey = Uint8Array

export function createSessionFingerprintKey(): SessionFingerprintKey {
  const key = new Uint8Array(32)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(key)
  } else {
    for (let i = 0; i < key.length; i++) key[i] = (Math.random() * 256) | 0
  }
  return key
}

/** Sync fingerprint for worker hot path. */
export function fingerprintCanonicalIdentitySync(
  key: SessionFingerprintKey,
  category: IdentityCategory,
  canonical: string,
  constraint?: import('./types').WireRepresentationConstraint,
  originalSpelling?: string,
): string {
  const registryKey = correlationRegistryKeyFromParts(category, canonical, constraint, originalSpelling)
  return fallbackFingerprint(key, `${FINGERPRINT_VERSION}:${registryKey}`)
}

/**
 * Compute a non-identifying fingerprint for a canonical identity.
 * Same category+canonical within one session yields the same fingerprint.
 */
export async function fingerprintCanonicalIdentity(
  key: SessionFingerprintKey,
  category: IdentityCategory,
  canonical: string,
): Promise<string> {
  const material = `${FINGERPRINT_VERSION}:${identityMappingKey(category, canonical)}`
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key as BufferSource,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    )
    const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(material))
    return bytesToHex(new Uint8Array(sig))
  }
  return fallbackFingerprint(key, material)
}

function fallbackFingerprint(key: SessionFingerprintKey, material: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < material.length; i++) {
    h ^= material.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  for (let i = 0; i < key.length; i++) {
    h ^= key[i]!
    h = Math.imul(h, 0x01000193)
  }
  return (h >>> 0).toString(16).padStart(8, '0')
}

function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0')
  }
  return out
}
