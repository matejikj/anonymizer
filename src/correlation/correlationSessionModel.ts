/**
 * Module-scoped correlation session — files, discoveries, and plans stay out of Zustand (Stage 23).
 */

import type {
  CorrelationSessionPhase,
  CorrelationSourceDiscovery,
  CorrelationSourcePlan,
  CorrelationSourceRecord,
  StagedSourceDescriptor,
} from './types'

export interface CorrelationSessionModel {
  sessionId: string
  generationId: string
  phase: CorrelationSessionPhase
  sources: Map<string, CorrelationSourceRecord>
  mappingRevision: number | null
  abort: AbortController | null
}

let active: CorrelationSessionModel | null = null

export function getCorrelationSessionModel(): CorrelationSessionModel | null {
  return active
}

export function clearCorrelationSessionModel(): void {
  active?.abort?.abort()
  active = null
}

export function createCorrelationSessionModel(input: {
  sessionId: string
  generationId: string
  descriptors: readonly StagedSourceDescriptor[]
  buildRecord: (d: StagedSourceDescriptor) => CorrelationSourceRecord
}): CorrelationSessionModel {
  clearCorrelationSessionModel()
  const sources = new Map<string, CorrelationSourceRecord>()
  for (const d of input.descriptors) {
    sources.set(d.sourceId, input.buildRecord(d))
  }
  active = {
    sessionId: input.sessionId,
    generationId: input.generationId,
    phase: 'staged',
    sources,
    mappingRevision: null,
    abort: null,
  }
  return active
}

export function updateSourceRecord(
  sourceId: string,
  patch: Partial<CorrelationSourceRecord>,
): void {
  if (!active) return
  const prev = active.sources.get(sourceId)
  if (!prev) return
  active.sources.set(sourceId, { ...prev, ...patch })
}

export function setCorrelationPhase(phase: CorrelationSessionPhase): void {
  if (!active) return
  active.phase = phase
}

export function setCorrelationMappingRevision(revision: number): void {
  if (!active) return
  active.mappingRevision = revision
}

export function setCorrelationAbort(controller: AbortController | null): void {
  if (!active) return
  active.abort = controller
}

export function listCorrelationSources(): readonly CorrelationSourceRecord[] {
  if (!active) return []
  return [...active.sources.values()]
}

export function getCorrelationSource(sourceId: string): CorrelationSourceRecord | null {
  return active?.sources.get(sourceId) ?? null
}

export function attachSourceDiscovery(sourceId: string, discovery: CorrelationSourceDiscovery): void {
  updateSourceRecord(sourceId, {
    discovery,
    phase: 'resolved',
    importState: 'ok',
    coverageState: 'ok',
  })
}

export function attachSourcePlan(sourceId: string, plan: CorrelationSourcePlan): void {
  updateSourceRecord(sourceId, {
    plan,
    phase: 'planned',
    exportState: 'ready',
    textReview: null,
  })
}

export function addSourceRecord(record: CorrelationSourceRecord): void {
  if (!active) return
  active.sources.set(record.sourceId, record)
}

export function removeSourceRecord(sourceId: string): boolean {
  if (!active) return false
  return active.sources.delete(sourceId)
}

export function setCorrelationGenerationId(generationId: string): void {
  if (!active) return
  active.generationId = generationId
}

export function resetCorrelationSourcesForRebuild(): void {
  if (!active) return
  for (const sourceId of active.sources.keys()) {
    updateSourceRecord(sourceId, {
      phase: 'staged',
      discovery: null,
      plan: null,
      textReview: null,
      exportState: 'blocked',
      importState: 'pending',
      coverageState: 'pending',
      errorCode: null,
      errorMessage: null,
    })
  }
}

export function appendStagedDescriptor(descriptor: StagedSourceDescriptor, buildRecord: (d: StagedSourceDescriptor) => CorrelationSourceRecord): void {
  if (!active) return
  active.sources.set(descriptor.sourceId, buildRecord(descriptor))
}
