/**
 * Correlation workspace orchestration (Stage 28–31).
 */

import { useAppStore } from '../app/store'
import { disposeActiveSession, cancelActiveOperation } from '../app/sessionLifecycleCoordinator'
import { getCorrelationView } from './correlationController'
import { resetCorrelationProgress } from './correlationProgressModel'
import {
  buildFlatOccurrenceList,
  getCorrelationWorkspaceSummary,
  pickInitialCorrelationSourceId,
  rememberSourceScroll,
  resetCorrelationReviewModel,
  selectCorrelationSource,
  setFlatOccurrenceCursor,
  sourceKindShort,
  sourceProblemReason,
} from './correlationReviewModel'
import { selectTextSourceForPreview } from './textMaterialization'
import { resetCorrelationExportModel } from './export/correlationExportModel'
import { setCorrelationUiPhase, resetCorrelationUiPhase } from './correlationPhaseModel'
import { announceCorrelationSource } from './correlationLiveAnnouncer'
import { listCorrelationSources, getCorrelationSource } from './correlationSessionModel'
import { resetCorrelationSourceUiContext } from './correlationSourceUiContext'
import type { OccurrenceRef } from '../mapping/types'
import { cs } from '../i18n/cs'

export function enterCorrelationProcessingPhase(): void {
  const generationId = getCorrelationView().generationId ?? ''
  setCorrelationUiPhase({ kind: 'processing', generationId })
}

export function enterCorrelationReviewPhase(options?: { preserveSelection?: boolean }): void {
  const generationId = getCorrelationView().generationId ?? ''
  setCorrelationUiPhase({ kind: 'review', generationId })
  useAppStore.getState().setStatusMessage('')
  if (options?.preserveSelection) {
    const selected = useAppStore.getState().selectedCorrelationSourceId
    if (selected && selected !== 'all' && getCorrelationSource(selected)) {
      return
    }
  }
  const initial = pickInitialCorrelationSourceId()
  if (initial) {
    selectCorrelationSource(initial)
  }
}

export async function cancelInitialCorrelationProcessing(): Promise<void> {
  // Abort + clear failed session state, but keep staging list for retry (Stage 31 / Stage 5).
  cancelActiveOperation()
}

/** Select the next problem source and surface its reason — works even without identities. */
export function focusCorrelationProblem(sourceId?: string): void {
  const summary = getCorrelationWorkspaceSummary()
  const id = sourceId ?? summary.nextProblemSourceId
  if (!id) return
  const source = getCorrelationSource(id)
  if (!source) return
  selectCorrelationSourceWithAnnounce(id)
  const reason = summary.nextProblemSourceId === id
    ? summary.nextProblemReason
    : sourceProblemReason(source)
  if (reason) {
    useAppStore.getState().setStatusMessage(reason)
    announceCorrelationSource(reason)
  }
}

export function leaveCorrelationReview(): void {
  resetCorrelationSourceUiContext()
  disposeActiveSession()
}

export function enterCorrelationExportingPhase(): void {
  const generationId = getCorrelationView().generationId ?? ''
  setCorrelationUiPhase({ kind: 'exporting', generationId })
}

export function enterCorrelationCompletedPhase(): void {
  const generationId = getCorrelationView().generationId ?? ''
  setCorrelationUiPhase({ kind: 'completed', generationId })
}

export function enterCorrelationFailedPhase(recoverTo: 'staging' | 'review'): void {
  const generationId = getCorrelationView().generationId
  setCorrelationUiPhase({ kind: 'failed', recoverTo, generationId })
}

export function finishCorrelationSessionAndClear(): void {
  leaveCorrelationReview()
}

export function selectCorrelationSourceWithAnnounce(sourceId: 'all' | string): void {
  selectCorrelationSource(sourceId)
  if (sourceId === 'all') {
    announceCorrelationSource(cs.correlationWorkspace.allSources(listCorrelationSources().length))
    return
  }
  const source = getCorrelationSource(sourceId)
  if (!source) return
  announceCorrelationSource(
    cs.correlationWorkspace.sourceAnnounced(source.fileName, sourceKindShort(source.kind)),
  )
}

function applySourceJump(ref: OccurrenceRef): void {
  selectCorrelationSourceWithAnnounce(ref.sourceId)
  if (ref.kind === 'text') {
    rememberSourceScroll(ref.sourceId, { line: ref.line })
    selectTextSourceForPreview(ref.sourceId)
  } else {
    rememberSourceScroll(ref.sourceId, { packetIndex: ref.packetIndex })
    // Clear a hiding display filter so the jumped packet is visible.
    void import('./revealPcapPacketForJump').then((m) => {
      if (useAppStore.getState().selectedCorrelationSourceId === ref.sourceId) {
        m.revealPcapPacketForJump(ref.packetIndex)
      }
    })
  }
}

/**
 * Jump to an occurrence whose position in the flat list is already known — e.g. the
 * ref returned by stepFlatOccurrence itself (Další/Předchozí). Skips the re-lookup
 * below: a packet-kind ref only carries (sourceId, packetIndex), which several
 * different entities can share (a packet routinely contains 2+ detected entities),
 * so re-finding it by structural match can resolve to the wrong list index and snap
 * the cursor back — no re-lookup is needed when the caller already knows the index.
 */
export function jumpToCorrelationOccurrenceAtCursor(ref: OccurrenceRef): void {
  applySourceJump(ref)
}

/** Jump to an arbitrary occurrence (e.g. clicking an entity row) and sync the flat-list
 * cursor to match, so subsequent Další/Předchozí continues from this position. */
export function jumpToCorrelationOccurrence(ref: OccurrenceRef): void {
  applySourceJump(ref)
  const list = buildFlatOccurrenceList()
  const idx = list.findIndex(
    (o) =>
      o.sourceId === ref.sourceId &&
      ((o.kind === 'text' && ref.kind === 'text' && o.line === ref.line && o.start === ref.start) ||
        (o.kind === 'packet' && ref.kind === 'packet' && o.packetIndex === ref.packetIndex)),
  )
  if (idx >= 0) setFlatOccurrenceCursor(idx)
}

export function getActiveCorrelationGenerationId(): string | null {
  return getCorrelationView().generationId
}

export function resetCorrelationWorkspaceForTests(): void {
  resetCorrelationReviewModel()
  resetCorrelationProgress()
  resetCorrelationExportModel()
  resetCorrelationUiPhase()
  resetCorrelationSourceUiContext()
}
