/**
 * Correlation multi-source export progress + completion state (Stage 29).
 */

import { useAppStore } from '../../app/store'
import type {
  CorrelationCompletionState,
  CorrelationExportJobPhase,
  CorrelationExportProgress,
} from './correlationExportTypes'

let phase: CorrelationExportJobPhase = 'idle'
let progress: CorrelationExportProgress = idleProgress()
let completion: CorrelationCompletionState | null = null

function idleProgress(): CorrelationExportProgress {
  return {
    phase: 'idle',
    fileIndex: 0,
    fileTotal: 0,
    currentFileName: '',
    currentMessage: '',
    completedFiles: [],
    remainingFiles: [],
    usedDirectoryPicker: false,
    usedMultiDownloadFallback: false,
    downloadUnverified: false,
  }
}

function bump(): void {
  useAppStore.getState().bumpCorrelationEpoch()
}

export function resetCorrelationExportModel(): void {
  phase = 'idle'
  progress = idleProgress()
  completion = null
  bump()
}

export function getCorrelationExportProgress(): CorrelationExportProgress {
  return progress
}

export function getCorrelationCompletionState(): CorrelationCompletionState | null {
  return completion
}

export function getCorrelationExportPhase(): CorrelationExportJobPhase {
  return phase
}

export function setCorrelationExportProgress(next: Partial<CorrelationExportProgress>): void {
  progress = { ...progress, ...next }
  phase = progress.phase
  bump()
}

export function markCorrelationExportComplete(state: CorrelationCompletionState): void {
  completion = state
  phase = 'done'
  progress = {
    ...progress,
    phase: 'done',
    currentMessage: '',
  }
  bump()
}

export function resetCorrelationExportForTests(): void {
  resetCorrelationExportModel()
}
