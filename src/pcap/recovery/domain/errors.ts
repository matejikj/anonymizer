/**
 * Stable PCAP recovery error codes (reversible anonymization).
 * Public codes are intentional; messages must never include passphrase,
 * keys, plaintext frames, or original identity values.
 */

export const PCAP_RECOVERY_ERROR = {
  invalidFormat: 'recovery-invalid-format',
  versionUnsupported: 'recovery-version-unsupported',
  oversize: 'recovery-oversize',
  pairMismatch: 'recovery-pair-mismatch',
  authFailed: 'recovery-auth-failed',
  footerInvalid: 'recovery-footer-invalid',
  frameOrder: 'recovery-frame-order',
  frameDuplicate: 'recovery-frame-duplicate',
  frameMissing: 'recovery-frame-missing',
  indexInvalid: 'recovery-index-invalid',
  sourceRange: 'recovery-source-range',
  sessionLocked: 'recovery-session-locked',
  sessionExpired: 'recovery-session-expired',
  queryInvalid: 'recovery-query-invalid',
  queryAmbiguous: 'recovery-query-ambiguous',
  packetNotFound: 'recovery-packet-not-found',
  outputLengthMismatch: 'recovery-output-length-mismatch',
  outputHashMismatch: 'recovery-output-hash-mismatch',
  cancelled: 'recovery-cancelled',
  internal: 'recovery-internal',
} as const

export type PcapRecoveryErrorCode =
  (typeof PCAP_RECOVERY_ERROR)[keyof typeof PCAP_RECOVERY_ERROR]

export const PCAP_RECOVERY_ERROR_CODES: readonly PcapRecoveryErrorCode[] = Object.freeze(
  Object.values(PCAP_RECOVERY_ERROR),
)

export type PcapRecoveryResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly code: PcapRecoveryErrorCode; readonly message: string }

export function recoveryFail<T>(
  code: PcapRecoveryErrorCode,
  message: string,
): PcapRecoveryResult<T> {
  return { ok: false, code, message }
}

export function recoveryOk<T>(value: T): PcapRecoveryResult<T> {
  return { ok: true, value }
}

/** Tamper / pairing failures share one public auth code (fail-closed). */
export function recoveryAuthFailed(
  message = 'Soubor pro obnovu je poškozený nebo nepatří k tomuto anonymizovanému souboru.',
): PcapRecoveryResult<never> {
  return recoveryFail(PCAP_RECOVERY_ERROR.authFailed, message)
}
