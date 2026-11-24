export type {
  ProfileCompatibilityOutcome,
  ProfileCompatibilityConflict,
  ProfileCompatibilityReport,
  CorrelationEffectivePolicy,
  TextEffectivePolicy,
  PcapEffectivePolicy,
  CorrelationProfileInput,
  CompileCorrelationPolicyOptions,
  CorrelationSessionPolicy,
  SessionCategoryResolution,
  ProfileConflictResolution,
  TextCategoryRepresentation,
  PcapCategoryRepresentation,
} from './types'

export { PROFILE_COMPATIBILITY_OUTCOME } from './types'

export {
  compileTextEffectivePolicy,
  compilePcapEffectivePolicy,
  compileCorrelationPolicy,
  hashEffectivePolicy,
} from './effectivePolicy'

export {
  evaluateProfileCompatibility,
  applyCategoryResolution,
  compatibilityAllowsProcessing,
  deriveSessionOutcome,
} from './compatibility'

export {
  classifyProfileImpact,
  classifyPcapPayloadPolicyChange,
  ProfileImpactKind,
  profileImpactBlocksExport,
  type ProfileImpact,
} from './profileImpactCompiler'

export {
  isWireValidIpv4,
  isWireValidIpv6,
  isWireCompatibleReplacement,
} from './wireValid'

export {
  resetCorrelationSessionPolicy,
  compileAndEvaluateSessionPolicy,
  getProfileCompatibilityReport,
  resolveProfileConflict,
  getCorrelationSessionPolicy,
  sessionPolicyAllowsProcessing,
  correlationResolveOptionsFromSessionPolicy,
  applySessionPolicyToCustomRules,
  isExportBlockedBySessionPolicy,
  setRebuildRequired,
} from './sessionPolicy'

export {
  runGlobalCorrelationRebuild,
  runGlobalCorrelationRebuildIfNeeded,
  requiresGlobalRebuild,
  isSourcePlanStaleWithManifest,
  assertManifestPlanConsistency,
  resetGlobalRebuildStateForTests,
  type GlobalRebuildResult,
} from './globalRebuild'
