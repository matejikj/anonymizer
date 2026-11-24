export type {
  AdapterKind,
  SourceAdapter,
  SourceLimits,
  ProbeResult,
  SourcePreflightResult,
  DiscoveryRequest,
  BuildPlanRequest,
  StagedSourceDescriptor,
  CorrelationSourceRecord,
  CorrelationSourceDiscovery,
  CorrelationSourcePlan,
  CorrelationTextReviewState,
  TextSourceDiscovery,
  PcapSourceDiscovery,
  TestSourceDiscovery,
  TextSourcePlan,
  PcapSourcePlan,
  TestSourcePlan,
  CorrelationSessionView,
  CorrelationSessionPhase,
  CorrelationError,
  CorrelationErrorCode,
  StageCorrelationResult,
  ProcessCorrelationResult,
  AddCorrelationSourceResult,
  RemoveCorrelationSourceResult,
} from './types'

export type { CorrelationSessionManifest } from './correlationManifest'

export {
  registerSourceAdapter,
  unregisterSourceAdapter,
  getSourceAdapter,
  clearSourceAdapterRegistry,
  registeredAdapterKinds,
  requireSourceAdapter,
} from './adapterRegistry'

export { SequentialGate, correlationResolveGate } from './sequentialGate'
export {
  correlationSourceLimits,
  validateDescriptorCount,
  validateAggregateBytes,
  validatePasteAggregateBytes,
  validateUniqueSourceIds,
  sumDescriptorBytes,
  sumExistingSourceBytes,
  sumPasteDescriptorBytes,
  perKindFileLimit,
  defaultOutputFileName,
} from './sourceLimits'

export { createTextSourceAdapter, textSourceAdapter } from './textSourceAdapter'
export { createPcapSourceAdapter, pcapSourceAdapter } from './pcapSourceAdapter'
export {
  getCorrelationSessionModel,
  clearCorrelationSessionModel,
  listCorrelationSources,
  getCorrelationSource,
} from './correlationSessionModel'

export {
  getCorrelationSessionView,
  isSingleSourceCorrelation,
  resetCorrelationViewModel,
} from './correlationViewModel'

export {
  getPublishedCorrelationManifest,
  publishCorrelationManifest,
  isCorrelationManifestStale,
  clearCorrelationManifest,
  resetCorrelationManifestForTests,
} from './correlationManifest'

export {
  runSourceTransaction,
  abortActiveSourceTransaction,
} from './correlationTransaction'

export {
  materializeTextForSource,
  releaseTextMaterialization,
  selectTextSourceForPreview,
  getMaterializedTextSourceId,
  countMaterializedTextSources,
} from './textMaterialization'

export { processCorrelationSession, buildStagedSourceRecord, collectSourceOccurrences } from './correlationSession'

export {
  bootstrapDefaultSourceAdapters,
  resetCorrelationAdaptersForTests,
  stageCorrelationDescriptors,
  runCorrelationSession,
  addCorrelationSource,
  removeCorrelationSource,
  cancelCorrelationSession,
  clearCorrelationSession,
  getCorrelationView,
  isSingleSourceSession,
  isPublishedManifestStale,
  selectCorrelationTextPreview,
  getCorrelationProfileCompatibilityReport,
  resolveProfileCompatibilityConflict,
} from './correlationController'

export type {
  StagingItem,
  StagingBatchSummary,
  ImportRoute,
} from './import/types'

export {
  probeSourceKind,
  preflightStagingFile,
  fileFingerprint,
  buildStagingItemsFromFiles,
  buildStagingSummary,
  getStagingItems,
  getReadyStagingItems,
  ingestDroppedFiles,
  handleUniversalFileDrop,
  openCorrelationStaging,
  leaveCorrelationStaging,
  addMoreStagingFiles,
  canConfirmCorrelationStaging,
  getStagingConfirmBlockedReason,
  confirmCorrelationStaging,
  getStagingProfileCompatibilityReport,
  resolveStagingProfileConflict,
  applyRecommendedStagingResolutions,
  resetCorrelationImportForTests,
  resetStagingForTests,
  UNIVERSAL_FILE_ACCEPT,
  routeSingleTextFile,
  routeSinglePcapFile,
} from './import'

export {
  getCorrelationProgressState,
  resetCorrelationProgress,
  initCorrelationProgress,
} from './correlationProgressModel'

export {
  buildCorrelationEntityRows,
  buildCrossFormatSharedCategoryCounts,
  getCorrelationWorkspaceSummary,
  resetCorrelationReviewModel,
  selectCorrelationSource,
  stepFlatOccurrence,
} from './correlationReviewModel'

export {
  enterCorrelationProcessingPhase,
  enterCorrelationReviewPhase,
  cancelInitialCorrelationProcessing,
  leaveCorrelationReview,
  jumpToCorrelationOccurrence,
  focusCorrelationProblem,
  finishCorrelationSessionAndClear,
  enterCorrelationExportingPhase,
  enterCorrelationCompletedPhase,
  enterCorrelationFailedPhase,
  selectCorrelationSourceWithAnnounce,
  resetCorrelationWorkspaceForTests,
} from './correlationWorkspaceController'

export type { CorrelationUiPhase } from './correlationPhaseModel'
export {
  getCorrelationUiPhase,
  setCorrelationUiPhase,
  resetCorrelationUiPhase,
  correlationUiPhaseKind,
} from './correlationPhaseModel'

export {
  announceCorrelationSource,
  resetCorrelationLiveAnnouncerForTests,
} from './correlationLiveAnnouncer'

export {
  buildCorrelationExportPreview,
  runCorrelationExport,
  cancelCorrelationExport,
  CorrelationExportCancelledError,
  correlationSetIsUnstableForExport,
  isExportPreviewStale,
} from './export/correlationExportController'

export { allocateUniqueOutputNames } from './export/uniqueOutputNames'

export type {
  CorrelationExportPreview,
  CorrelationExportProgress as CorrelationExportProgressState,
  CorrelationExportOutcome,
  CorrelationCompletionState,
  CorrelationExportScope,
} from './export/correlationExportTypes'

export {
  buildShareableCorrelationManifest,
  assertShareableManifestHasNoLeaks,
  needsShareableCorrelationManifest,
  resetShareableManifestCounterForTests,
  SHAREABLE_MANIFEST_FILE_NAME,
} from './export/correlationShareManifest'

export {
  getCorrelationExportProgress,
  getCorrelationCompletionState,
  resetCorrelationExportModel,
  resetCorrelationExportForTests,
} from './export/correlationExportModel'

export { assessCorrelationSourceExport } from './export/correlationExportSecurity'

export type { ProfileCompatibilityReport } from './profileCompatibility'
export {
  compileCorrelationPolicy,
  compileTextEffectivePolicy,
  compilePcapEffectivePolicy,
  evaluateProfileCompatibility,
  classifyProfileImpact,
  ProfileImpactKind,
  profileImpactBlocksExport,
  PROFILE_COMPATIBILITY_OUTCOME,
  runGlobalCorrelationRebuild,
  isSourcePlanStaleWithManifest,
  requiresGlobalRebuild,
  compileAndEvaluateSessionPolicy,
  resolveProfileConflict,
  sessionPolicyAllowsProcessing,
} from './profileCompatibility'
