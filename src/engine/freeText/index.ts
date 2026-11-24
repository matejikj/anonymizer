/**
 * T69 — free-text allowlist + consistent pseudonymization (shared text/PCAP API).
 */

export type {
  FreeTextLevel,
  FreeTextOp,
  FreeTextVocabulary,
  FreeTextToken,
  FreeTextPreserveReason,
  FreeTextMaskReason,
} from './types.ts'

export {
  sanitizeFreeText,
  type SanitizeFreeTextInput,
} from './sanitizeFreeText.ts'

export {
  defaultFreeTextVocabulary,
  bundledVocabulary,
  interimVocabulary,
  INTERIM_VOCABULARY_VERSION,
  isVocabularyWord,
  FREE_TEXT_VOCABULARY_VERSION,
  FREE_TEXT_VOCABULARY_HASH,
  FREE_TEXT_VOCABULARY_BIN_NAME,
  FREE_TEXT_VOCABULARY_BUILT_AT,
  FREE_TEXT_VOCABULARY_WORD_COUNT,
  FREE_TEXT_VOCABULARY_MAX_AGE_DAYS,
} from './vocabulary.ts'

export { tokenizeFreeText } from './tokenize.ts'

export {
  learnTemplateSafeTokens,
  templateKey,
  type TemplateLearnOptions,
} from './templates.ts'

export {
  findTypedSpans,
  classifyDigitToken,
  type TypedSpan,
} from './typedValues.ts'

export {
  applyFreeTextOpsToString,
  type FreeTextMapResolver,
} from './applyToString.ts'

export { applyFreeTextAnalyzePass } from './analyzePass.ts'

export {
  emptyTextDispositionAggregate,
  aggregateFreeTextOps,
  withFailedRules,
  withAliasSuppressions,
  gateFromTextDispositionLedger,
  type TextDisposition,
  type TextDispositionLedgerAggregate,
} from './textDispositionLedger.ts'
