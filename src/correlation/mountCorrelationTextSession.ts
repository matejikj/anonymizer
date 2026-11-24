/**
 * Mount a text review session from correlation source data for ReviewPanel + editor toggles.
 */

import type { Entity, EntitySummary } from '../domain/types'
import { patchEntitySummariesFromSnapshot } from '../engine/entityRegistry'
import { applyEffectiveMatchFlags } from '../features/review/entityState'
import { buildSessionModel, clearSessionModel, getSessionModel } from '../features/workspace/sessionModel'
import { getSharedMappingClient } from '../mapping/sharedMappingClient'
import { useAppStore } from '../app/store'
import type { CorrelationTextReviewState, TextSourceDiscovery, TextSourcePlan } from './types'
import { applyTextReviewToSessionEntities } from './publishCorrelationTextReview'
import {
  beginSourceMount,
  clearSourceMountToken,
  isSourceMountCurrent,
  makeSourceMountToken,
} from './correlationSourceUiContext'

function summariesToEntities(summaries: readonly EntitySummary[]): Entity[] {
  return summaries.map((s) => ({
    key: s.key,
    category: s.category,
    originalSample: s.originalSample,
    normalized: s.normalized,
    replacement: s.replacement,
    occurrenceCount: s.occurrenceCount,
    occurrenceIndexes: new Uint32Array(0),
    enabled: s.enabled,
    source: s.source,
    sourceId: s.sourceId,
    createdOrder: s.createdOrder,
  }))
}

export function mountCorrelationTextSession(input: {
  readonly text: string
  readonly discovery: TextSourceDiscovery
  readonly plan: TextSourcePlan
  readonly textReview?: CorrelationTextReviewState | null
  /** Reject apply if a newer source mount started (stale async). */
  readonly mountToken?: string
}): (() => void) | null {
  const token =
    input.mountToken ?? makeSourceMountToken(input.plan.sourceId, input.plan.generationId)
  beginSourceMount(token)

  clearSessionModel()
  const canonical = input.text.replace(/\r\n?/g, '\n')
  const mode = canonical.length > 2_000_000 ? 'large' : 'common'
  buildSessionModel({
    text: canonical,
    detection: input.discovery.detection,
    fileName: input.discovery.fileName,
    byteLength: input.discovery.byteLength,
    mode,
    lineEndings: input.discovery.lineEndings,
    workerPlanTrusted: false,
  })

  if (!isSourceMountCurrent(token)) {
    clearSessionModel()
    return null
  }

  const session = getSessionModel()
  if (!session) return () => clearSessionModel()

  const snapshot = getSharedMappingClient().getPublishedSnapshot()
  const summaries = snapshot
    ? patchEntitySummariesFromSnapshot(input.discovery.detection.entities, snapshot)
    : input.discovery.detection.entities
  session.entities = summariesToEntities(summaries)
  session.entitySummaries = [...summaries]
  session.packed = input.plan.packed
  session.plan = input.plan.plan

  if (input.textReview) {
    applyTextReviewToSessionEntities(input.textReview)
  } else {
    applyEffectiveMatchFlags(session.packed, session.entities, session.categoryMasters)
  }

  if (!isSourceMountCurrent(token)) {
    clearSessionModel()
    return null
  }

  useAppStore.getState().bumpSessionEpoch()

  return () => {
    if (isSourceMountCurrent(token)) clearSourceMountToken()
    clearSessionModel()
  }
}
