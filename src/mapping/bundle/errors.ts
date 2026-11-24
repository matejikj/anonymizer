/**
 * Mapping bundle codec error codes (Stage 20).
 * Fail-closed — no plaintext fallback on decode failure.
 */

export const BUNDLE_CODEC_ERROR = {
  oversize: 'bundle-oversize',
  payloadInvalid: 'bundle-payload-invalid',
  identityOverflow: 'bundle-identity-overflow',
  aliasOverflow: 'bundle-alias-overflow',
  occurrenceOverflow: 'bundle-occurrence-overflow',
  internal: 'bundle-internal',
} as const

export type BundleCodecErrorCode = (typeof BUNDLE_CODEC_ERROR)[keyof typeof BUNDLE_CODEC_ERROR]

export type BundleCodecResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly code: BundleCodecErrorCode; readonly message: string }

export function bundleFail<T>(
  code: BundleCodecErrorCode,
  message: string,
): BundleCodecResult<T> {
  return { ok: false, code, message }
}

export function bundleOk<T>(value: T): BundleCodecResult<T> {
  return { ok: true, value }
}
