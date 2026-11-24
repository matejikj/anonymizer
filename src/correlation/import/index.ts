export type {
  StagingItem,
  StagingItemReady,
  StagingItemError,
  StagingItemDuplicate,
  StagingBatchSummary,
  ImportRoute,
  SourceProbeResult,
  DetectedSourceKind,
} from './types'

export {
  readFileHead,
  probeSourceKind,
  preflightStagingFile,
  fileFingerprint,
  aggregateLimitMessage,
  stagingAggregateLimitBytes,
} from './sourcePreflightPort'

export {
  detectCompressedFormat,
  decompressGzipToFile,
  stripGzipExtension,
  DecompressError,
  MAX_INFLATED_BYTES,
} from './decompressInput.ts'
export type { CompressedFormat, DecompressErrorCode } from './decompressInput.ts'

export { resolveInputFile, formatGzipInflationNote } from './resolveInputFile.ts'
export type { ResolveInputResult } from './resolveInputFile.ts'
export type { GzipInflationNote } from './types.ts'

export {
  formatInputRejection,
  rejectionForUnsupportedCode,
  rejectionForCompressedFormat,
} from './inputRejection.ts'
export type { InputRejection } from './inputRejection.ts'

export {
  getStagingItems,
  getStagingRevision,
  getReadyStagingItems,
  buildStagingSummary,
  buildStagingItemsFromFiles,
  mergeFilesIntoStaging,
  removeStagingItem,
  clearStagingItems,
  replaceStagingItems,
  formatStagingSize,
  resetStagingForTests,
  getLastSupportBundleOmissions,
  getLastSupportBundleMeta,
} from './stagingModel'
export type { LastSupportBundleMeta } from './stagingModel'

export {
  handleUniversalFileDrop,
  ingestDroppedFiles,
  routeSingleTextFile,
  routeSinglePcapFile,
  openCorrelationStaging,
  leaveCorrelationStaging,
  addMoreStagingFiles,
  confirmCorrelationStaging,
  canConfirmCorrelationStaging,
  getStagingConfirmBlockedReason,
  getStagingProfileCompatibilityReport,
  resolveStagingProfileConflict,
  applyRecommendedStagingResolutions,
  resetCorrelationImportForTests,
  singleFileStagingErrorMessage,
  continueCorrelationStagingWithSingleFile,
  UNIVERSAL_FILE_ACCEPT,
} from './correlationImportController'
