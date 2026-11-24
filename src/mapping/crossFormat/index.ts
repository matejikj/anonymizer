export {
  CROSS_FORMAT_CANONICALIZATION_VERSION,
  type CrossFormatCategory,
  type CrossFormatCategoryContract,
  type CrossFormatSourceKind,
  type RepresentationCompatibility,
  type RepresentationStrategy,
} from './types'

export {
  canonicalizeCrossFormatCategory,
  canonicalizeCrossFormatEmail,
  canonicalizeCrossFormatHostname,
  canonicalizeCrossFormatIpv4,
  canonicalizeCrossFormatIpv6,
  canonicalizeCrossFormatMac,
  canonicalizeCrossFormatPhone,
  canonicalizeCrossFormatPort,
  canonicalizeCrossFormatUser,
} from './canonicalizers'

export {
  CROSS_FORMAT_REPRESENTATION_STRATEGIES,
  constraintsCompatible,
  isFixedTextTokenAlias,
  representationStrategyFor,
} from './representation'

export {
  alternateLookupKeys,
  crossFormatCategoryFromIdentity,
  crossFormatRegistryKey,
  crossFormatRegistryKeyFromIdentity,
  isFormatLocalOnlyCategory,
  storageCategoryForCrossFormat,
  usesCrossFormatTextEngine,
  usesSharedWireEngine,
} from './categories'

export {
  CROSS_FORMAT_CATEGORY_CONTRACTS,
  assertCrossFormatContractComplete,
  getCrossFormatContract,
} from './contractRegistry'

export {
  correlationRegistryKey,
  correlationRegistryKeyFromParts,
  registryKeyForResolve,
  crossFormatCanonicalForIdentity,
  findSnapshotEntryForIdentity,
  lookupCrossFormatAlias,
  buildCrossFormatAliasLookup,
} from './identityKey'
