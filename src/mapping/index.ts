export type {
  CanonicalIdentity,
  MappingSnapshot,
  MappingPlanSnapshot,
  MappingSessionSnapshot,
  MappingSnapshotEntry,
  ResolveRequest,
  ResolveResult,
  WireRepresentationConstraint,
  MappingConfig,
  EntityCategory,
  IdentityCategory,
  AliasDisposition,
  IdentitySourceRef,
  OccurrenceRef,
  RepresentationAlias,
  MappingRegistryEntry,
} from './types'
export {
  mappingKey,
  buildAliasLookup,
  buildMultiAliasLookup,
  RESOLVE_ERROR,
  MAPPING_SNAPSHOT_CONSUMERS,
  isMappingPlanSnapshot,
  isMappingSessionSnapshot,
  requireSessionSnapshot,
} from './types'
export { MappingAuthority } from './mappingAuthority'
export { MappingRegistry, primaryAlias, aliasForConstraint, aliasForSnapshotConstraint } from './mappingRegistry'
export { MappingWorkerClient, nextMappingRequestId, type MappingClientStatus } from './mappingWorkerClient'
export {
  MAPPING_PROTOCOL_VERSION,
  MAPPING_WORKER_ERROR,
  validateProtocolVersion,
  validateResolveIdentities,
  snapshotToWire,
  snapshotFromWire,
  type MappingWorkerRequest,
  type MappingWorkerResponse,
} from './protocol'
export {
  canonicalizePcapIdentity,
  defaultWireConstraint,
  maxCanonicalStringLength,
} from './pcapCanonical'
export {
  canonicalizeIdentity,
  canonicalizeTextIdentity,
  defaultIdentityWireConstraint,
  identityMappingKey,
  categoriesShareCanonical,
} from './canonicalize'
export {
  CROSS_FORMAT_CANONICALIZATION_VERSION,
  CROSS_FORMAT_CATEGORY_CONTRACTS,
  assertCrossFormatContractComplete,
  correlationRegistryKey,
  lookupCrossFormatAlias,
  crossFormatCategoryFromIdentity,
  constraintsCompatible,
} from './crossFormat'
export {
  canonicalizeTextIdentity as canonicalizeTextCategory,
  defaultTextWireConstraint,
} from './textCanonical'
export {
  collectTextIdentities,
  registerEntitiesFromSnapshot,
  textIdentityFromMatch,
} from './textIdentity'
export {
  resolveTextIdentities,
  resolveTextIdentitiesBatch,
  getTextMappingClient,
  setTextMappingClientForTests,
} from './textMappingPort'
export {
  getSharedMappingClient,
  resetSharedMappingClient,
  setSharedMappingClientForTests,
} from './sharedMappingClient'
export { releaseMappingSession } from './sessionLifecycle'
export { lookupOriginal, lookupAlias, releaseOccurrence } from './mappingLookupPort'
export {
  exactLookupByAlias,
  scanAiReport,
  annotateAiReport,
  loadAliasIndex,
  loadAliasIndexFromSnapshot,
  loadAliasIndexFromPayload,
  AliasLookupIndex,
  AhoCorasick,
  scanReportForPseudonyms,
  buildAnnotatedReport,
  type ResolveMappingSource,
  type ResolveLookupCandidate,
  type ExactLookupResult,
  type ReportFinding,
  type ScanReportResult,
  type ResolveError,
  type ResolveErrorCode,
} from './resolve'
export {
  MAPPING_BUNDLE_FORMAT,
  BUNDLE_CODEC_ERROR,
  type MappingBundlePayload,
  type BundleCodecErrorCode,
  type BundleCodecResult,
} from './bundle'
export { OccurrenceIndex, occurrenceRefKey, packedOccurrenceByteSize } from './occurrenceIndex'
export { ReverseIndex, type ReverseLookupCandidate } from './reverseIndex'
export {
  createSessionFingerprintKey,
  fingerprintCanonicalIdentity,
  fingerprintCanonicalIdentitySync,
} from './identityFingerprint'
export type { TextIdentityCategory, PcapIdentityCategory } from './identityCategories'
export { isPcapIdentityCategory, isTextIdentityCategory, ALL_IDENTITY_CATEGORIES } from './identityCategories'
