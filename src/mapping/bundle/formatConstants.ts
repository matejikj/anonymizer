/**
 * Mapping bundle wire format constants.
 * Logical format: rnd-log-anonymizer-mapping-bundle / schemaVersion 1 — plain JSON, no encryption.
 */

import { MAPPING_CAPABILITY_LIMITS } from '../../domain/capabilityContract'

export const MAPPING_BUNDLE_FORMAT = 'rnd-log-anonymizer-mapping-bundle' as const
export const MAPPING_BUNDLE_FORMAT_VERSION = 1
export const MAPPING_BUNDLE_SCHEMA_VERSION = 1
export const MAPPING_BUNDLE_CANONICALIZATION_VERSION = 1

export const BUNDLE_FIELD_LIMITS = {
  sessionIdBytes: 128,
  sourceIdBytes: 256,
  sourceNameBytes: 512,
  canonicalBytes: 1024,
  aliasBytes: 1024,
} as const

export const BUNDLE_WIRE_LIMITS = {
  maxBundleBytes: MAPPING_CAPABILITY_LIMITS.maxBundleBytes,
  maxBundleImportBytes: MAPPING_CAPABILITY_LIMITS.maxBundleImportBytes,
  maxIdentities: MAPPING_CAPABILITY_LIMITS.maxIdentities,
  maxAliasesPerIdentity: MAPPING_CAPABILITY_LIMITS.maxAliasesPerIdentity,
  maxSources: MAPPING_CAPABILITY_LIMITS.maxSourcesPerSession,
} as const
