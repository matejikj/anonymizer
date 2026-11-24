export {
  EntityRegistry,
  ENTITY_CATEGORIES,
  type EntityCategory,
  type EntityRecord,
  MAX_ENTITY_CARDINALITY,
} from './entityRegistry';
export { SessionMapping, DEFAULT_MAPPING_CONFIG, type MappingConfig } from './mapping';
export { TimestampMapping } from './timestampMapping';
export { FingerprintSession, addU32Mod, readU32, u32ToBytes } from './fingerprintSession';
export { expandSeedToEntropy, freshEntropy } from './seedEntropy';
export {
  createProductionSessionMapping,
  createTestSessionMapping,
  assertProductionMappingHasNoFixedSeed,
  isTestModeMappingSeed,
  TEST_MODE_SEED_MIN_LENGTH,
  FORBIDDEN_PRODUCTION_DEFAULT_SEEDS,
  type MappingSessionOptions,
} from './testModeSeed';
export {
  allocateExclusiveId,
  allocateExclusiveIdSparse,
  type DenseProbeCursor,
} from './exclusiveIdAllocation';
export {
  MAPPING_DOMAIN_SPECS,
  IPV4_BLOCK_DOMAIN_SIZE,
  DYNAMIC_PORT_PAIR_DOMAIN_SIZE,
  USER_REGISTERED_PORT_PAIR_DOMAIN_SIZE,
  mappingDomainFor,
  assertMappingDomainsComplete,
  type MappingDomainSpec,
  type MappingDomainKind,
} from './mappingDomainRegistry';
export {
  ENTITY_NAMESPACES,
  entityNamespaceFor,
  entityMapKey,
  namespacesMustStayIsolated,
  ipModeForProfile,
  isIpMappingMode,
  type EntityNamespace,
  type IpMappingMode,
} from './entityNamespaces';
