/**
 * Mapping bundle codec public exports.
 * UI and domain import from here — not from payload/JSON-codec internals.
 */

export {
  BUNDLE_CODEC_ERROR,
  type BundleCodecErrorCode,
  type BundleCodecResult,
} from './errors'
export {
  MAPPING_BUNDLE_FORMAT,
  MAPPING_BUNDLE_FORMAT_VERSION,
  MAPPING_BUNDLE_SCHEMA_VERSION,
  MAPPING_BUNDLE_CANONICALIZATION_VERSION,
  BUNDLE_WIRE_LIMITS,
} from './formatConstants'
export type {
  MappingBundlePayload,
  MappingBundleEntry,
  MappingBundleSource,
} from './types'
export { buildBundlePayloadFromSnapshot, bundleFileName } from './buildPayload'
export {
  isMappingBundleJsonBytes,
  isMappingBundleJsonFileName,
  serializeMappingBundleJson,
  parseMappingBundleJsonText,
  parseMappingBundleJsonBytes,
  MAPPING_BUNDLE_JSON_EXTENSION,
  MAPPING_BUNDLE_JSON_SCHEMA_URN,
} from './mappingBundleJsonCodec'
export { validatePayloadLimits } from './payloadCodec'
