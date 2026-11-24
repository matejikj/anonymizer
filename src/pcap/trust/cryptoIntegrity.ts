/**
 * Enterprise step 6 — cryptographic_integrity status.
 *
 * Transport checksums can be VALID while TLS Finished / STUN MESSAGE-INTEGRITY /
 * STIR Identity are MODIFIED after sanitization. This module aggregates signals
 * from plan coverage / issues without embedding original values.
 */

import type { ValidityStatus } from '../trust/validity'
import type { LayerCoverage } from '../sanitize/types'

const CRYPTO_ISSUE_MARKERS = [
  'crypto-integrity-modified',
  'sip-identity',
  'identity-header',
  'tls-finished',
  'tls-certificate',
  'stun-message-integrity',
  'message-integrity',
] as const

/**
 * Issue codes sanitizers should push when they break application crypto
 * (Identity mask, TLS handshake rewrite, STUN MESSAGE-INTEGRITY).
 */
export const CRYPTO_INTEGRITY_ISSUE = {
  tls: 'crypto-integrity-modified:tls',
  sipIdentity: 'crypto-integrity-modified:sip-identity',
  stunMi: 'crypto-integrity-modified:stun-message-integrity',
} as const

export function issueImpliesCryptoModified(issue: string): boolean {
  const lower = issue.toLowerCase()
  return CRYPTO_ISSUE_MARKERS.some((m) => lower.includes(m))
}

export function resolveCryptographicIntegrity(input: {
  readonly coverage?: readonly LayerCoverage[]
  readonly issues?: readonly string[]
  /** Explicit override from caller. */
  readonly explicit?: ValidityStatus
}): ValidityStatus {
  if (input.explicit) return input.explicit

  for (const issue of input.issues ?? []) {
    if (issueImpliesCryptoModified(issue)) return 'MODIFIED'
  }

  for (const span of input.coverage ?? []) {
    if (
      (span.protocol === 'tls-clienthello'
        || span.protocol === 'tls-serverhello'
        || span.protocol === 'tls-certificate'
        || span.protocol === 'tls')
      && (span.status === 'covered' || span.status === 'redacted')
    ) {
      // TLS ClientHello SNI map / cert mask invalidates Finished/transcript.
      return 'MODIFIED'
    }
  }

  return 'UNKNOWN'
}
