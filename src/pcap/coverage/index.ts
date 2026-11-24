export type {
  UnifiedCoverageModel,
  UnifiedLayerCoverage,
  UnifiedProtocolSummary,
  UnifiedCoverageSource,
  UnifiedCoverageStatus,
  EntityOccurrenceIndex,
} from './types'
export {
  buildUnifiedCoverageModel,
  structuralSpansFromNode,
  unifiedSpansForPacket,
  unifiedProtocols,
  packetHasProtocol,
  countUnsupportedFromUnified,
  type StructuralSpanInput,
} from './buildUnifiedCoverage'
export {
  dominantStatus,
  mergePacketSpans,
  mergeSpanPair,
  effectiveAnonymizationStatus,
  isBlockingUnsupported,
} from './mergeRules'
export { SANITIZER_PROTOCOL_IDS, isSanitizerProtocol, allKnownProtocols } from './protocolRegistry'
export {
  PROTOCOL_FAMILY_IDS,
  familyForProtocol,
  protocolFamilyLabel,
  isUnsupportedProtocolId,
  unsupportedProtocolName,
  isFilterableProtocolToken,
  type ProtocolFamilyId,
  type ProtocolFamilyRef,
} from './protocolFamilies'
export {
  PackedEntityOccurrenceIndex,
  buildOccurrenceIndexFromIntents,
} from './entityOccurrenceIndex'
export {
  buildSessionCoverage,
  entityOccurrencesToWire,
  entityOccurrenceListsFromWire,
  type WireEntityOccurrence,
} from './sessionCoverage'
export {
  buildPcapCoverageViewModel,
  buildPlanRevision,
  coverageStatusToUiStatus,
  dominantUiStatus,
  dominantUiStatusForSpans,
  layerKindFromCounts,
  spanExportAction,
  userVerdictForProtocol,
  type PcapCoverageViewModel,
  type PcapProtocolCoverageRow,
  type PcapSpanCoverageRow,
  type PcapCoverageSummary,
  type DominantUiStatus,
  type UserCoverageVerdict,
  type SpanExportAction,
  type CoverageLayerKind,
  type PrimaryExportAction,
} from './pcapCoverageViewModel'
export {
  buildVoipObservability,
  formatVoipObservabilityLines,
  type VoipObservabilitySummary,
} from './voipObservability'
