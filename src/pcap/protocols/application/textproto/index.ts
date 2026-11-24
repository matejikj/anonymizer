/**
 * T15 — text protocol toolkit (line/header tokenizer, extractors, payload detectors).
 */

export {
  DEFAULT_TEXTPROTO_PARSE_LIMITS,
  type TextProtoParseLimits,
} from './limits'

export {
  decodeLatin1,
  type TextProtoByteSpan,
} from './bytes'

export {
  tokenizeTextProtoMessage,
  type TextProtoMessage,
  type TextProtoHeader,
  type TextProtoParseIssue,
} from './tokenizer'

export {
  dispositionForTextProtoHeader,
  type TextProtoHeaderAction,
  type TextProtoHeaderPolicyEntry,
  type TextProtoHeaderPolicyTable,
} from './headerPolicy'

export {
  extractTextProtoValues,
  type TextProtoExtractedValue,
} from './extractors'

export {
  detectIdentitiesInPayload,
  type PayloadDetectorHit,
  type PayloadDetectorOptions,
} from './payloadDetectors'

export {
  findSqlLiteralSpans,
  findKeyValueValueSpans,
  maskLiteralSpans,
  looksLikePostgresDollarQuote,
  sqlDialectRequiresMaskWhenNoLiterals,
  type LiteralMaskSpan,
  type SqlLiteralDialect,
  type FindSqlLiteralOptions,
} from './literalMask'

export {
  findEncodedAuthTokenSpans,
  maskEncodedAuthTokens,
  type EncodedTokenSpan,
} from './encodedTokens'

export {
  applyPayloadMapHits,
  hitsFromDetectors,
  hitsFromExtractors,
  maskPayloadSpan,
  type PayloadMapHit,
} from './applyPayloadMaps'

export {
  sanitizeTextPayload,
  type SanitizeTextPayloadResult,
} from './sanitizeTextPayload'

export {
  GENERIC_NOTIFY_HEADER_POLICY,
  GENERIC_NOTIFY_CORPUS,
  matchesGenericNotifyStartLine,
} from './profiles/genericNotify'
