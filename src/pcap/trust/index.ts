/**
 * Enterprise trust foundation (step 1) — vocabulary for classification, validity, export gate.
 * Step 5 — coverage bookkeeping, leak scanner, diagnostic residual risk.
 *
 * profile ≠ gate ≠ validity — never collapse into one enum.
 */

export type {
  FieldClassification,
  SensitiveField,
  PolicyAction,
} from './classification'
export {
  FIELD_CLASSIFICATIONS,
  isFieldClassification,
} from './classification'

export type {
  PolicyApplyContext,
  ClassificationPolicyTable,
  PolicyAppliedField,
  SanitizationPipelineStage,
} from './policyTables'
export {
  DIAGNOSTIC_CLASSIFICATION_POLICY,
  HIGH_PRIVACY_CLASSIFICATION_POLICY,
  classificationPolicyTable,
  actionForClassification,
  applyPolicy,
  forbidsPacketDrop,
  SANITIZATION_PIPELINE_STAGES,
  sanitizationPolicyRealizesTable,
  timingActionForProfile,
  expectedTimestampsMode,
} from './policyTables'

export type {
  ValidityStatus,
  ExportValidityLayers,
  BuildValidityLayersInput,
} from './validity'
export {
  VALIDITY_STATUSES,
  isValidityStatus,
  isExportValidityLayers,
  buildValidityLayers,
} from './validity'

export type {
  GateResult,
  GateBadge,
  LegacyGateResult,
  ExportGateChecks,
  ResolveExportGateInput,
  ExportGateOutcome,
} from './exportGate'
export {
  GATE_RESULTS,
  LEGACY_GATE_RESULTS,
  isGateResult,
  isGateBadge,
  normalizeGateResult,
  resolveExportGate,
  resolveTextExportGate,
  gateBadgeFromShareableWithAi,
  worstGateResult,
  isSafeForAi,
  isAiReadyWithGaps,
} from './exportGate'

export type { SanitizationCoverageSummary } from './coverageBookkeeping'
export {
  summarizeSanitizationCoverage,
  buildGateChecksFromCoverage,
} from './coverageBookkeeping'

export type {
  LeakCategory,
  LeakScanOriginal,
  LeakScanFinding,
  LeakScanResult,
} from './leakScanner'
export {
  LEAK_CATEGORIES,
  mapEntityCategoryToLeak,
  scanArtifactForOriginalLeaks,
  emptyLeakScanResult,
} from './leakScanner'

export type { DiagnosticResidualRisk } from './diagnosticResidualRisk'
export { buildDiagnosticResidualRisk } from './diagnosticResidualRisk'

export {
  CRYPTO_INTEGRITY_ISSUE,
  issueImpliesCryptoModified,
  resolveCryptographicIntegrity,
} from './cryptoIntegrity'
