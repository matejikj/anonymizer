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
  interimVocabulary,
  INTERIM_VOCABULARY_VERSION,
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
