/**
 * Publish text Inspector toggles from the mounted SessionModel into the
 * correlation source record (plan + textReview + export state).
 */

import { buildReplacementPlan } from '../engine/transform'
import {
  ALL_CATEGORIES,
  applyEffectiveMatchFlags,
  createDefaultCategoryMasters,
  type CategoryMasterMap,
} from '../features/review/entityState'
import { getSessionModel } from '../features/workspace/sessionModel'
import { useAppStore } from '../app/store'
import type { Category } from '../domain/types'
import { SourceKind as SK } from '../domain/sourceArtifact'
import {
  getCorrelationSource,
  updateSourceRecord,
} from './correlationSessionModel'
import { assessCorrelationSourceExport } from './export/correlationExportSecurity'
import type { CorrelationTextReviewState, TextSourcePlan } from './types'

function mastersFromReview(review: CorrelationTextReviewState | null | undefined): CategoryMasterMap {
  const masters = createDefaultCategoryMasters()
  if (!review) return masters
  for (const cat of ALL_CATEGORIES) {
    const v = review.categoryMasters[cat]
    if (typeof v === 'boolean') masters[cat] = v
  }
  return masters
}

export function applyTextReviewToSessionEntities(
  review: CorrelationTextReviewState | null | undefined,
): CategoryMasterMap {
  const session = getSessionModel()
  const masters = mastersFromReview(review)
  if (!session) return masters
  session.categoryMasters = masters
  if (review) {
    session.entities = session.entities.map((e) => ({
      ...e,
      enabled: review.entityEnabled[e.key] ?? e.enabled,
    }))
    session.entitySummaries = session.entitySummaries.map((e) => ({
      ...e,
      enabled: review.entityEnabled[e.key] ?? e.enabled,
    }))
  }
  applyEffectiveMatchFlags(session.packed, session.entities, session.categoryMasters)
  session.plan = buildReplacementPlan(session.packed, session.entities)
  return masters
}

/** Snapshot current SessionModel toggles into the correlation source plan. */
export function publishCorrelationTextReviewFromSession(sourceId: string): boolean {
  const record = getCorrelationSource(sourceId)
  const session = getSessionModel()
  if (!record || !session) return false
  if (record.plan?.kind !== 'text') return false

  applyEffectiveMatchFlags(session.packed, session.entities, session.categoryMasters)
  session.plan = buildReplacementPlan(session.packed, session.entities)

  const entityEnabled: Record<string, boolean> = {}
  for (const e of session.entities) {
    entityEnabled[e.key] = e.enabled
  }
  const categoryMasters: Record<string, boolean> = {}
  for (const cat of ALL_CATEGORIES) {
    categoryMasters[cat] = session.categoryMasters[cat as Category] ?? true
  }
  const textReview: CorrelationTextReviewState = { categoryMasters, entityEnabled }

  const nextPlan = {
    ...record.plan,
    plan: session.plan,
    packed: session.packed,
  } satisfies TextSourcePlan

  // Keep discovery entity enabled flags aligned for export security assessment.
  let discovery = record.discovery
  if (discovery?.kind === 'text') {
    discovery = {
      ...discovery,
      detection: {
        ...discovery.detection,
        entities: discovery.detection.entities.map((e) => ({
          ...e,
          enabled: entityEnabled[e.key] ?? e.enabled,
        })),
      },
    }
  }

  updateSourceRecord(sourceId, {
    plan: nextPlan,
    discovery,
    textReview,
  })

  const updated = getCorrelationSource(sourceId)
  if (!updated) return false
  const security = assessCorrelationSourceExport(updated)
  updateSourceRecord(sourceId, {
    exportState: security === 'blocked' ? 'blocked' : 'ready',
    coverageState:
      security === 'exposed' || security === 'gaps'
        ? 'partial'
        : updated.coverageState === 'partial'
          ? 'partial'
          : 'ok',
  })

  useAppStore.getState().bumpCorrelationEpoch()
  return true
}

export function getActiveCorrelationTextSourceId(): string | null {
  const selected = useAppStore.getState().selectedCorrelationSourceId
  if (!selected || selected === 'all') return null
  const record = getCorrelationSource(selected)
  if (!record) return null
  if (record.kind === SK.Text) return selected
  return null
}
