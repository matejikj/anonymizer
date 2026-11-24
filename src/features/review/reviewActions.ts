/**
 * Review panel actions — entity/category toggles + Worker plan rebuild (Krok 6).
 */

import type { Category } from '../../domain/types.ts'
import { getClientForReview } from '../../app/sessionController.ts'
import { getSessionModel } from '../workspace/sessionModel.ts'
import { getDualLogBridge } from '../workspace/editorBridge.ts'
import { useAppStore } from '../../app/store.ts'
import {
  applyWorkerPlanBuffers,
  setCategoryMaster,
  toggleEntityEnabled,
} from './planController.ts'

/** Above this match count, category toggles also rebuild via Worker. */
export const CATEGORY_WORKER_THRESHOLD = 5_000

export function notifyPlanChanged(): void {
  useAppStore.getState().bumpSessionEpoch()
  getDualLogBridge()?.refreshDecorations()
  if (useAppStore.getState().phase === 'correlation-review') {
    void import('../../correlation/publishCorrelationTextReview.ts').then((m) => {
      const sourceId = m.getActiveCorrelationTextSourceId()
      if (sourceId) m.publishCorrelationTextReviewFromSession(sourceId)
    })
  }
}

export function actionToggleEntity(entityKey: string, enabled: boolean): boolean {
  const ok = toggleEntityEnabled(entityKey, enabled)
  if (ok) notifyPlanChanged()
  return ok
}

export async function actionToggleCategory(
  category: Category,
  enabled: boolean,
): Promise<boolean> {
  const bitset = setCategoryMaster(category, enabled)
  if (!bitset) return false
  notifyPlanChanged()

  const session = getSessionModel()
  if (!session?.workerPlanTrusted) return true
  if (session.meta.matchCount < CATEGORY_WORKER_THRESHOLD) return true

  const client = getClientForReview()
  const requestId = client.getActiveRequestId()
  if (!requestId) return true

  try {
    useAppStore.getState().setStatusMessage('Přepočítávám náhrady…')
    // Transfer a copy — local bitset stays usable
    const copy = bitset.buffer.slice(
      bitset.byteOffset,
      bitset.byteOffset + bitset.byteLength,
    ) as ArrayBuffer
    const buffers = await client.buildPlan(requestId, copy)
    applyWorkerPlanBuffers(buffers)
    notifyPlanChanged()
    useAppStore.getState().setStatusMessage('Kategorie aktualizována')
  } catch {
    // Local plan already applied; Worker rebuild is best-effort.
    useAppStore.getState().setStatusMessage('Kategorie aktualizována (lokální plán)')
  }
  return true
}

export function actionJumpToEntity(entityKey: string): void {
  const session = getSessionModel()
  if (!session) return
  const entity = session.entities.find((e) => e.key === entityKey)
  if (!entity) return
  // First match with this entity index
  const idx = session.entities.indexOf(entity)
  let matchIndex = -1
  for (let i = 0; i < session.packed.starts.length; i++) {
    if (session.packed.entityIndexes[i] === idx) {
      matchIndex = i
      break
    }
  }
  if (matchIndex < 0) return
  const bridge = getDualLogBridge()
  bridge?.jumpToMatchIndex(matchIndex)
  useAppStore.getState().setOccurrenceIndex(matchIndex)
}
