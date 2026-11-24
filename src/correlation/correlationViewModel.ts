/**
 * Correlation session view model — small IDs/state only (Stage 23).
 */

import {
  clearCorrelationSessionModel,
  getCorrelationSessionModel,
  listCorrelationSources,
} from './correlationSessionModel'
import type { CorrelationSessionView } from './types'

export function getCorrelationSessionView(): CorrelationSessionView {
  const model = getCorrelationSessionModel()
  if (!model) {
    return {
      sessionId: null,
      generationId: null,
      phase: 'empty',
      sourceCount: 0,
      mappingRevision: null,
      sourceIds: [],
    }
  }
  const sources = listCorrelationSources()
  return {
    sessionId: model.sessionId,
    generationId: model.generationId,
    phase: model.phase,
    sourceCount: sources.length,
    mappingRevision: model.mappingRevision,
    sourceIds: sources.map((s) => s.sourceId),
  }
}

export function isSingleSourceCorrelation(): boolean {
  const view = getCorrelationSessionView()
  return view.sourceCount === 1
}

export function resetCorrelationViewModel(): void {
  clearCorrelationSessionModel()
}
