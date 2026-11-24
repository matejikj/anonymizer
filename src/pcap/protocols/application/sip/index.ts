export type {
  ByteSpan,
  SipBody,
  SipHeader,
  SipMessage,
  SipParameter,
  SipParseDiagnostics,
  SipParseResult,
  SipRequestStartLine,
  SipResponseStartLine,
  SipStartLine,
  SipUri,
} from './types';
export { spanEnd, spansEqual } from './types';

export type { SipParseLimits } from './limits';
export { DEFAULT_SIP_PARSE_LIMITS } from './limits';

export {
  decodeLatin1Span,
  decodeUtf8Span,
  sliceSpan,
} from './bytes';

export { parseSipUri, parseHeaderParameters } from './uri';
export { looksLikeSipStart } from './startLine';
export { parseHeaderLine, headerNameEquals } from './header';
export {
  parseSipMessage,
  parseSipMessages,
  type ParseSipMessageOptions,
  type ParseSipMessagesOptions,
  type ParseSipMessagesResult,
  type ParsedSipMessageEntry,
} from './parser';
export { canonicalizeHeaderName } from './compact';
export {
  classifySipPayload,
  isSipPortHint,
  SIP_PORT,
  SIP_TLS_PORT,
  type ClassifySipPayloadOptions,
  type SipPayloadClassification,
} from './classify';

export {
  decideSipBodyPolicy,
  bodyCoverageStatus,
  sipMessageContentEncoding,
  type SipBodyDecision,
  type SipBodyDecisionKind,
} from './bodyPolicy';

export {
  planSipBodyOperations,
  isSiprecMetadataContentType,
  type SipBodyOperation,
  type SipBodyPlanResult,
  type SipBodyCoverageProtocol,
} from './bodyOperations';

export {
  parseSipMultipartBody,
  isMultipartContentType,
  isSdpPartContentType,
  type SipMultipartPart,
  type SipMultipartParseResult,
} from './multipartBody';

export type {
  SipEntityKind,
  SipEntityAction,
  SipMappingCategory,
  SipSensitiveEntity,
  SipExtractionResult,
  SipRedactionOperation,
  SipRedactionPlan,
} from './entities';
export {
  dispositionForHeader,
  CORRELATION_PARAMETERS,
  type SipHeaderDisposition,
} from './headerPolicy';
export { extractSipEntities, entityActionRequiresMapping, isCredentialEntity, mappingCategoryForEntity, type ExtractSipEntitiesOptions } from './extract';
export {
  buildSipRedactionPlan,
  applySipRedactionPlan,
  delimitersPreserved,
  planExcludesCredentialsFromMapping,
  SIP_REDACT_MASK_BYTE,
  type BuildRedactionPlanOptions,
} from './redactPlan';
export { hostMappingCategory } from './hostKind';
export {
  sanitizeStructuredSipMessage,
  buildCombinedSipSdpPlan,
  applyCombinedSipSdpPlan,
} from './sanitizeApply';
export { wirePortCanonical, resolveIdentityAlias } from './mappingWire';
export {
  recordSipSdpDiscoveryIntents,
} from './discoverIntents';
