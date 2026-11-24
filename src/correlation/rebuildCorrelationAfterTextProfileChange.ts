/**
 * Rebuild correlation text plans after text profile / custom-rule changes.
 */

import { useAppStore } from '../app/store'
import { SourceKind as SK } from '../domain/sourceArtifact'
import {
  getCorrelationSessionModel,
  listCorrelationSources,
  setCorrelationGenerationId,
  setCorrelationMappingRevision,
  setCorrelationPhase,
  updateSourceRecord,
} from './correlationSessionModel'
import { processCorrelationSession } from './correlationSession'
import { publishCorrelationManifest } from './correlationManifest'
import { resetCorrelationSourcesForRebuild } from './correlationSessionModel'
import { setRebuildRequired } from './profileCompatibility/sessionPolicy'
import { getSharedMappingClient } from '../mapping/sharedMappingClient'
import { cs } from '../i18n/cs'

/**
 * Full reprocess of the open set after a text-profile change.
 * Blocks export while running; preserves session id; remaps identities.
 */
export async function rebuildCorrelationAfterTextProfileChange(): Promise<void> {
  if (useAppStore.getState().phase !== 'correlation-review') return
  const model = getCorrelationSessionModel()
  if (!model || model.sources.size === 0) return

  const hasTextLike = listCorrelationSources().some((s) => s.kind === SK.Text)
  if (!hasTextLike) return

  useAppStore.getState().setPlanBusy(true)
  setRebuildRequired(true)
  useAppStore.getState().setStatusMessage(cs.correlationWorkspace.rebuildBanner)
  useAppStore.getState().bumpCorrelationEpoch()

  for (const source of listCorrelationSources()) {
    updateSourceRecord(source.sourceId, { exportState: 'blocked' })
  }

  try {
    const sessionId = model.sessionId
    const newGenerationId = `gen-profile-${Date.now().toString(36)}`
    setCorrelationGenerationId(newGenerationId)
    resetCorrelationSourcesForRebuild()
    setCorrelationPhase('staged')

    await getSharedMappingClient().resetSession()

    const processed = await processCorrelationSession()
    if (!('mappingRevision' in processed)) {
      setRebuildRequired(true)
      useAppStore.getState().setStatusMessage(
        'message' in processed ? processed.message : cs.correlationWorkspace.rebuildBanner,
      )
      return
    }

    publishCorrelationManifest({
      sessionId,
      generationId: newGenerationId,
      mappingRevision: processed.mappingRevision,
      sourceIds: listCorrelationSources().map((s) => s.sourceId),
    })
    setCorrelationMappingRevision(processed.mappingRevision)
    setRebuildRequired(false)
    useAppStore.getState().setStatusMessage('')
  } finally {
    useAppStore.getState().setPlanBusy(false)
    useAppStore.getState().bumpCorrelationEpoch()
  }
}
