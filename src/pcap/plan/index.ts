export { SnapshotMappingAdapter } from './snapshotMappingAdapter'
export {
  buildSanitizationFromSnapshot,
  buildDeterministicPlan,
  planWireSignature,
} from './deterministicPlanBuilder'
export {
  PlanInvariantError,
  PacketParseError,
  isPlanBlockingError,
  toPlanInvariantError,
  planInvariantSafeReasonCode,
} from './planErrors'
export {
  validateMappingClosure,
  resolveSnapshotWithMappingClosure,
  identitiesForClosureFailures,
  dedupeIdentities,
  throwMappingClosureFailure,
  type MappingClosureFailure,
  type MappingClosureValidationResult,
  type MappingClosureResolveResult,
} from './mappingClosureValidation'
export { mergePatchesStrict } from './mergePatchesStrict'
export {
  emptyPlanChangeCounts,
  emptyPlanAuditFields,
  addPlanChangeCounts,
  derivePlanPacketAccounting,
  deriveDispositionReason,
  type PlanChangeCounts,
  type PlanChangeCategory,
  type PlanDispositionReason,
} from './planDisposition'
