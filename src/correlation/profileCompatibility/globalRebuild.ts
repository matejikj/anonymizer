/**
 * Global correlation rebuild — atomic new generation and snapshots (Stage 26).
 */

import { getSharedMappingClient } from '../../mapping/sharedMappingClient'
import {
  getCorrelationSessionModel,
  resetCorrelationSourcesForRebuild,
  setCorrelationGenerationId,
  setCorrelationMappingRevision,
  setCorrelationPhase,
} from '../correlationSessionModel'
import {
  clearCorrelationManifest,
  getPublishedCorrelationManifest,
  publishCorrelationManifest,
} from '../correlationManifest'
import { processCorrelationSession } from '../correlationSession'
import type { CorrelationError } from '../types'
import { ProfileImpactKind, profileImpactBlocksExport, type ProfileImpact } from './profileImpactCompiler'
import {
  getCorrelationSessionPolicy,
  resetCorrelationSessionPolicy,
  setRebuildRequired,
} from './sessionPolicy'

export interface GlobalRebuildResult {
  readonly ok: true
  readonly sessionId: string
  readonly generationId: string
  readonly mappingRevision: number
}

export function isSourcePlanStaleWithManifest(input: {
  planGenerationId: string
  planMappingRevision: number
  sessionGenerationId: string
  manifestMappingRevision: number
}): boolean {
  if (input.planGenerationId !== input.sessionGenerationId) return true
  if (input.planMappingRevision !== input.manifestMappingRevision) return true
  return false
}

export function requiresGlobalRebuild(impact: ProfileImpact): boolean {
  return profileImpactBlocksExport(impact)
    && impact.kind === ProfileImpactKind.RepresentationPolicy
}

export async function runGlobalCorrelationRebuild(
  impact: ProfileImpact,
): Promise<GlobalRebuildResult | CorrelationError> {
  if (!requiresGlobalRebuild(impact)) {
    return {
      code: 'correlation-not-ready',
      message: 'Global rebuild requires representation-policy impact',
    }
  }

  const model = getCorrelationSessionModel()
  if (!model) {
    return { code: 'correlation-not-staged', message: 'No correlation session for rebuild' }
  }

  setRebuildRequired(true)

  const mappingClient = getSharedMappingClient()
  await mappingClient.resetSession()

  const newGenerationId = `gen-rebuild-${Date.now().toString(36)}`
  setCorrelationGenerationId(newGenerationId)
  resetCorrelationSourcesForRebuild()
  setCorrelationPhase('staged')
  clearCorrelationManifest()
  setRebuildRequired(false)

  const processed = await processCorrelationSession()
  if (!('mappingRevision' in processed)) {
    setRebuildRequired(true)
    return processed
  }

  const refreshed = getCorrelationSessionModel()
  const manifest = publishCorrelationManifest({
    sessionId: model.sessionId,
    generationId: newGenerationId,
    mappingRevision: processed.mappingRevision,
    sourceIds: refreshed ? [...refreshed.sources.keys()] : [...model.sources.keys()],
  })

  setCorrelationMappingRevision(processed.mappingRevision)
  setRebuildRequired(false)

  void getCorrelationSessionPolicy()

  return {
    ok: true,
    sessionId: model.sessionId,
    generationId: newGenerationId,
    mappingRevision: manifest.mappingRevision,
  }
}

export async function runGlobalCorrelationRebuildIfNeeded(
  impact: ProfileImpact,
): Promise<GlobalRebuildResult | CorrelationError | null> {
  if (!requiresGlobalRebuild(impact)) return null
  return runGlobalCorrelationRebuild(impact)
}

export function assertManifestPlanConsistency(): boolean {
  const manifest = getPublishedCorrelationManifest()
  const model = getCorrelationSessionModel()
  if (!manifest || !model) return true

  for (const record of model.sources.values()) {
    if (!record.plan) continue
    if (isSourcePlanStaleWithManifest({
      planGenerationId: record.plan.generationId,
      planMappingRevision: record.plan.mappingRevision,
      sessionGenerationId: model.generationId,
      manifestMappingRevision: manifest.mappingRevision,
    })) {
      return false
    }
  }
  return true
}

export function resetGlobalRebuildStateForTests(): void {
  setRebuildRequired(false)
  resetCorrelationSessionPolicy()
}
