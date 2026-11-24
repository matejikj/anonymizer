/**
 * CorrelationSession — discover → resolve → plan orchestration (Stage 23 / 24 transactions).
 */

import { getSharedMappingClient } from '../mapping/sharedMappingClient'
import type { OccurrenceRef } from '../mapping/types'
import {
  attachSourceDiscovery,
  attachSourcePlan,
  getCorrelationSessionModel,
  setCorrelationAbort,
  setCorrelationMappingRevision,
  setCorrelationPhase,
  updateSourceRecord,
} from './correlationSessionModel'
import { publishCorrelationManifest } from './correlationManifest'
import { runSourceTransaction, abortActiveSourceTransaction } from './correlationTransaction'
import {
  initCorrelationProgress,
  markCorrelationSourceActive,
  markCorrelationSourceDone,
  markCorrelationSourceFailed,
  reportCorrelationSessionPhase,
  reportCorrelationSourceProgress,
  finishCorrelationProgress,
} from './correlationProgressModel'
import type {
  CorrelationError,
  ProcessCorrelationResult,
  StagedSourceDescriptor,
} from './types'
import { defaultOutputFileName } from './sourceLimits'

function failSource(sourceId: string, code: string, message: string): void {
  updateSourceRecord(sourceId, {
    phase: 'failed',
    importState: 'failed',
    exportState: 'blocked',
    errorCode: code,
    errorMessage: message,
  })
}

export async function processCorrelationSession(): Promise<ProcessCorrelationResult | CorrelationError> {
  const model = getCorrelationSessionModel()
  if (!model) {
    return { code: 'correlation-not-staged', message: 'No staged correlation session' }
  }
  if (model.phase !== 'staged') {
    return { code: 'correlation-not-staged', message: `Session phase is ${model.phase}, expected staged` }
  }

  setCorrelationPhase('processing')
  initCorrelationProgress('Hledám společné hodnoty a připravuji bezpečné náhrady.')

  const sourceIds = [...model.sources.keys()]
  if (sourceIds[0]) {
    markCorrelationSourceActive(sourceIds[0], 'Připravuji společnou relaci…')
  }
  reportCorrelationSessionPhase('Připravuji společnou relaci…')

  const mappingClient = getSharedMappingClient()
  await mappingClient.resetSession()

  const abort = new AbortController()
  setCorrelationAbort(abort)
  let lastRevision = 0

  try {
    for (const sourceId of sourceIds) {
      if (abort.signal.aborted) {
        await abortActiveSourceTransaction()
        finishCorrelationProgress(false, 'Analýza zrušena')
        return { code: 'correlation-cancelled', message: 'Correlation processing cancelled' }
      }

      const record = model.sources.get(sourceId)
      if (!record) continue

      updateSourceRecord(sourceId, { phase: 'discovering', importState: 'pending' })
      markCorrelationSourceActive(sourceId)

      const committed = await runSourceTransaction({
        generationId: model.generationId,
        sourceId,
        record,
        signal: abort.signal,
        onProgress: (phase, done, total) => {
          reportCorrelationSourceProgress(sourceId, phase, done, total)
        },
      })

      if (!('discovery' in committed)) {
        const err = committed
        failSource(sourceId, err.code, err.message)
        markCorrelationSourceFailed(sourceId, err.message)
        setCorrelationPhase('failed')
        finishCorrelationProgress(false, 'Analýza selhala')
        return err
      }

      attachSourceDiscovery(sourceId, committed.discovery)
      attachSourcePlan(sourceId, committed.plan)
      markCorrelationSourceDone(sourceId, committed.discovery.identities.length)
      lastRevision = committed.snapshot.mappingRevision
      setCorrelationMappingRevision(lastRevision)
    }

    setCorrelationPhase('ready')
    setCorrelationAbort(null)
    finishCorrelationProgress(true, 'Analýza dokončena')
    publishCorrelationManifest({
      sessionId: model.sessionId,
      generationId: model.generationId,
      mappingRevision: lastRevision,
      sourceIds,
    })

    return {
      ok: true,
      sessionId: model.sessionId,
      mappingRevision: lastRevision,
      sourceCount: sourceIds.length,
    }
  } catch (e) {
    await abortActiveSourceTransaction()
    setCorrelationPhase('failed')
    finishCorrelationProgress(false, 'Analýza selhala')
    const message = e instanceof Error ? e.message : String(e)
    return { code: 'correlation-discover-failed', message }
  }
}

export async function processSingleSourceInSession(
  sourceId: string,
  signal?: AbortSignal,
): Promise<{ ok: true; mappingRevision: number } | CorrelationError> {
  const model = getCorrelationSessionModel()
  if (!model) {
    return { code: 'correlation-not-staged', message: 'No correlation session' }
  }

  const record = model.sources.get(sourceId)
  if (!record) {
    return { code: 'correlation-source-missing', message: `Unknown source: ${sourceId}`, sourceId }
  }

  updateSourceRecord(sourceId, { phase: 'discovering', importState: 'pending' })

  const committed = await runSourceTransaction({
    generationId: model.generationId,
    sourceId,
    record,
    signal,
  })

  if (!('discovery' in committed)) {
    failSource(sourceId, committed.code, committed.message)
    return committed
  }

  attachSourceDiscovery(sourceId, committed.discovery)
  attachSourcePlan(sourceId, committed.plan)
  setCorrelationMappingRevision(committed.snapshot.mappingRevision)

  publishCorrelationManifest({
    sessionId: model.sessionId,
    generationId: model.generationId,
    mappingRevision: committed.snapshot.mappingRevision,
    sourceIds: [...model.sources.keys()],
  })

  return { ok: true, mappingRevision: committed.snapshot.mappingRevision }
}

export function collectSourceOccurrences(
  sourceId: string,
): OccurrenceRef[] {
  const record = getCorrelationSessionModel()?.sources.get(sourceId)
  if (!record?.discovery) return []

  const out: OccurrenceRef[] = []
  for (const id of record.discovery.identities) {
    if (id.occurrence && id.occurrence.sourceId === sourceId) {
      out.push(id.occurrence)
    }
  }
  return out
}

export function buildStagedSourceRecord(descriptor: StagedSourceDescriptor) {
  return {
    sourceId: descriptor.sourceId,
    kind: descriptor.kind,
    fileName: descriptor.file.name,
    outputFileName: descriptor.outputFileName ?? defaultOutputFileName(descriptor.kind, descriptor.file.name),
    byteLength: descriptor.file.size,
    phase: 'staged' as const,
    importState: 'pending' as const,
    coverageState: 'pending' as const,
    exportState: 'pending' as const,
    file: descriptor.file,
    inputKind: descriptor.inputKind ?? 'file',
    discovery: null,
    plan: null,
    textReview: null,
    errorCode: null,
    errorMessage: null,
    split: descriptor.split,
  }
}
