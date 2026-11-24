/**
 * Mapping bundle payload size/limit validation.
 */

import { BUNDLE_FIELD_LIMITS, BUNDLE_WIRE_LIMITS, MAPPING_BUNDLE_CANONICALIZATION_VERSION } from './formatConstants'
import { BUNDLE_CODEC_ERROR, bundleFail, type BundleCodecResult } from './errors'
import type { MappingBundlePayload } from './types'

export function validatePayloadLimits(payload: MappingBundlePayload): BundleCodecResult<void> {
  if (payload.sources.length > BUNDLE_WIRE_LIMITS.maxSources) {
    return bundleFail(BUNDLE_CODEC_ERROR.payloadInvalid, 'too many sources')
  }
  if (payload.entries.length > BUNDLE_WIRE_LIMITS.maxIdentities) {
    return bundleFail(BUNDLE_CODEC_ERROR.identityOverflow, 'too many entries')
  }
  if (payload.canonicalizationVersion !== MAPPING_BUNDLE_CANONICALIZATION_VERSION) {
    return bundleFail(BUNDLE_CODEC_ERROR.payloadInvalid, 'unsupported canonicalization version')
  }
  const sessionBytes = new TextEncoder().encode(payload.sessionId).byteLength
  if (sessionBytes > BUNDLE_FIELD_LIMITS.sessionIdBytes) {
    return bundleFail(BUNDLE_CODEC_ERROR.payloadInvalid, 'session id too long')
  }
  return { ok: true, value: undefined }
}
