export { buildLineIndex, splitPhysicalLines, joinPhysicalLines } from './lineIndex.ts'
export type { LineIndex } from './lineIndex.ts'
export {
  entityKey,
  normalizeByCategory,
  normalizeIp,
  normalizeHostname,
  normalizeEmail,
  normalizePerson,
  normalizeUserId,
  normalizeInternalId,
  normalizeSipPhone,
} from './normalize.ts'
export { resolveOverlaps, compareRawMatches } from './resolveOverlaps.ts'
export {
  nextReplacement,
  createReplacementCounters,
  createEntityRegistry,
  registerEntities,
} from './replacements.ts'
export { buildEntityMap, toEntitySummaries } from './entityRegistry.ts'
export {
  packResolvedMatches,
  entityKeyToIndex,
  toTransferableBuffers,
  fromTransferableBuffers,
  lowerBoundStart,
  matchesOverlapping,
  FLAG_ENABLED,
} from './packedMatchIndex.ts'
export type { PackedMatchBuffers } from './packedMatchIndex.ts'
export {
  transform,
  transformWithPlan,
  transformSlice,
  buildReplacementPlan,
  buildTransformSegments,
  planAndOffsetMap,
} from './transform.ts'
export type { ReplacementPlan } from './transform.ts'
export { createOffsetMap } from './offsetMap.ts'
export { analyze } from './analyze.ts'
export type { AnalysisResult } from './analyze.ts'
export { runAllDetectors, BUILTIN_DETECTORS } from './detectors/index.ts'
export * from './detectors/index.ts'
export { detectOnPhysicalLine } from './detectLine.ts'
export {
  sanitizeFreeText,
  applyFreeTextOpsToString,
  applyFreeTextAnalyzePass,
  defaultFreeTextVocabulary,
  learnTemplateSafeTokens,
  tokenizeFreeText,
  INTERIM_VOCABULARY_VERSION,
} from './freeText/index.ts'
export type {
  FreeTextLevel,
  FreeTextOp,
  FreeTextVocabulary,
  SanitizeFreeTextInput,
  FreeTextMapResolver,
} from './freeText/index.ts'
export { lineMatchWindow, matchesForOriginalRange } from './lineMap.ts'
export { buildLineColumnMap, mapPhysicalLine } from './columnMap.ts'
export type { LineColumnMap } from './columnMap.ts'
