/**
 * Correlation session manifest — tracks published source list and mapping revision (Stage 24).
 * Stale when exported manifest sourceIds or mappingRevision no longer match the live session.
 */

import { getCorrelationSessionView } from './correlationViewModel'

export interface CorrelationSessionManifest {
  readonly sessionId: string
  readonly generationId: string
  readonly mappingRevision: number
  readonly sourceIds: readonly string[]
  readonly manifestRevision: number
}

let publishedManifest: CorrelationSessionManifest | null = null
let manifestRevisionCounter = 0

export function getPublishedCorrelationManifest(): CorrelationSessionManifest | null {
  return publishedManifest
}

export function publishCorrelationManifest(input: {
  sessionId: string
  generationId: string
  mappingRevision: number
  sourceIds: readonly string[]
}): CorrelationSessionManifest {
  manifestRevisionCounter++
  publishedManifest = {
    sessionId: input.sessionId,
    generationId: input.generationId,
    mappingRevision: input.mappingRevision,
    sourceIds: Object.freeze([...input.sourceIds]),
    manifestRevision: manifestRevisionCounter,
  }
  return publishedManifest
}

export function clearCorrelationManifest(): void {
  publishedManifest = null
}

export function isCorrelationManifestStale(manifest: CorrelationSessionManifest): boolean {
  const view = getCorrelationSessionView()
  if (view.sessionId !== manifest.sessionId) return true
  if (view.mappingRevision !== manifest.mappingRevision) return true
  if (view.sourceIds.length !== manifest.sourceIds.length) return true
  for (let i = 0; i < manifest.sourceIds.length; i++) {
    if (view.sourceIds[i] !== manifest.sourceIds[i]) return true
  }
  return false
}

export function resetCorrelationManifestForTests(): void {
  publishedManifest = null
  manifestRevisionCounter = 0
}
