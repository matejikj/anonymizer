/**
 * Per-source export security assessment for correlation session (Stage 29 / T08).
 */

import { countUnsupportedFromUnified } from '../../pcap/coverage/buildUnifiedCoverage'
import { SourceKind as SK } from '../../domain/sourceArtifact'
import {
  ALL_CATEGORIES,
  computeExposedSummary,
  computeSecurityLevel,
  createDefaultCategoryMasters,
  type CategoryMasterMap,
} from '../../features/review/entityState'
import type { Category, Entity } from '../../domain/types'
import type { CorrelationSourceRecord, CorrelationTextReviewState } from '../types'
import type { CorrelationExportSecurity } from './correlationExportTypes'
import { resolveCoverageDisposition } from '../../pcap/sanitize/coverageDisposition'
import {
  resolveTextExportGate,
  type GateResult,
  worstGateResult,
} from '../../pcap/trust/exportGate'

function mastersFromReview(review: CorrelationTextReviewState | null): CategoryMasterMap {
  const masters = createDefaultCategoryMasters()
  if (!review) return masters
  for (const cat of ALL_CATEGORIES) {
    const v = review.categoryMasters[cat]
    if (typeof v === 'boolean') masters[cat] = v
  }
  return masters
}

function textLikeEntitiesFromRecord(record: CorrelationSourceRecord): Entity[] {
  if (record.discovery?.kind !== 'text') return []
  const enabledMap = record.textReview?.entityEnabled
  return record.discovery.detection.entities.map((e) => ({
    key: e.key,
    category: e.category,
    originalSample: e.originalSample,
    normalized: e.normalized,
    replacement: e.replacement,
    occurrenceCount: e.occurrenceCount,
    occurrenceIndexes: new Uint32Array(0),
    enabled: enabledMap?.[e.key] ?? e.enabled,
    source: e.source,
    sourceId: e.sourceId,
    createdOrder: e.createdOrder,
  }))
}

function gateToSecurity(gate: GateResult): CorrelationExportSecurity {
  switch (gate) {
    case 'AI_READY':
      return 'ready'
    case 'AI_READY_WITH_GAPS':
      return 'gaps'
    case 'NOT_AI_READY':
      return 'exposed'
    default:
      return 'blocked'
  }
}

export function securityToGate(security: CorrelationExportSecurity): GateResult {
  switch (security) {
    case 'ready':
      return 'AI_READY'
    case 'gaps':
      return 'AI_READY_WITH_GAPS'
    case 'exposed':
    case 'blocked':
      return 'NOT_AI_READY'
    default:
      return 'NOT_AI_READY'
  }
}

export function assessCorrelationSourceExport(record: CorrelationSourceRecord): CorrelationExportSecurity {
  if (record.phase === 'failed' || record.exportState === 'blocked') return 'blocked'
  if (record.phase !== 'planned' || record.exportState !== 'ready') return 'blocked'

  if (record.kind === SK.Text && record.discovery?.kind === 'text') {
    const entities = textLikeEntitiesFromRecord(record)
    const masters = mastersFromReview(record.textReview)
    const exposed = computeExposedSummary(entities, masters)
    const failedRuleIds = record.discovery.detection.failedRuleIds ?? []
    const level = computeSecurityLevel({
      analysisDone: true,
      failedRuleIds,
      exposed,
    })
    const incidentCount = record.discovery.detection.incidents?.totalFailures ?? 0
    if (level === 'blocked') return 'blocked'
    return gateToSecurity(
      resolveTextExportGate({
        failedRuleIds,
        incidentCount,
        exposedEntityCount: exposed.entityCount,
      }).gate,
    )
  }

  if (record.kind === SK.Pcap && record.discovery?.kind === 'pcap') {
    const discovery = record.discovery
    const policy = discovery.policy
    const unsupported = countUnsupportedFromUnified(discovery.discovery.unifiedCoverage)
    const fatalIssues = discovery.container.issues.filter((i) => i.severity >= 2)
    if (fatalIssues.length > 0 || discovery.discovery.analysis.entityOverflow) return 'blocked'
    if (unsupported > 0) {
      const disposition = resolveCoverageDisposition(policy, 'unsupported', 'generic')
      if (disposition === 'preserve-unsafe') return 'exposed'
      if (
        disposition === 'mask-in-place'
        || disposition === 'mask-application-in-place'
        || disposition === 'truncate'
        || disposition === 'drop'
        || disposition === 'strip-media-payload'
      ) {
        return 'gaps'
      }
      return 'exposed'
    }
    const incidentCount =
      record.plan?.kind === 'pcap' ? (record.plan.plan.incidents?.totalFailures ?? 0) : 0
    if (incidentCount > 0) return 'gaps'
    return 'ready'
  }

  if (record.kind === SK.Text || record.kind === SK.Pcap) return 'blocked'
  return 'ready'
}

export function correlationSourceExposedHint(
  record: CorrelationSourceRecord,
  security: CorrelationExportSecurity,
): string | null {
  if (security !== 'exposed') return null
  if (record.kind === SK.Pcap && record.discovery?.kind === 'pcap') {
    return 'pcap-exposed'
  }
  return 'text-exposed'
}

/** Whether any text category/entity was turned off (export may still be ready but exposed). */
export function textSourceHasDisabledValues(record: CorrelationSourceRecord): boolean {
  if (!record.textReview) return false
  for (const cat of ALL_CATEGORIES) {
    if (record.textReview.categoryMasters[cat as Category] === false) return true
  }
  return Object.values(record.textReview.entityEnabled).some((v) => v === false)
}

/** Worst-of gate across exportable correlation sources. */
export function worstCorrelationSecurity(
  securities: readonly CorrelationExportSecurity[],
): CorrelationExportSecurity {
  let gate: GateResult = 'AI_READY'
  let saw = false
  for (const s of securities) {
    if (s === 'blocked') continue
    saw = true
    gate = worstGateResult(gate, securityToGate(s))
  }
  if (!saw) return 'blocked'
  return gateToSecurity(gate)
}
