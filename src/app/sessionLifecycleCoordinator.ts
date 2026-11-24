/**
 * SessionLifecycleCoordinator — single public lifecycle entry (Stage 5).
 * Owns session kind + generation token; large data stays in module-scoped models.
 * Zustand is updated only as UI projection.
 */

import { useAppStore } from './store'
import { createIdleProgress } from '../features/import-log/importProgress'
import { cs } from '../i18n/cs'
import {
  type SessionKind,
  isLifecycleTransitionAllowed,
  requiresExclusiveDispose,
  LIFECYCLE_RESOURCE_INVENTORY,
  ZUSTAND_FORBIDDEN_PAYLOADS,
} from './sessionLifecycleInventory'
import { disposeNonTextSessionResources } from './sessionLifecycleDispose'
import {
  abortTextImportWork,
  disposeDetectionClientOnly,
  runFileAnalysis,
  runPasteAnalysis,
} from './sessionController'
import { ImportCancelledError } from '../features/import-log/streamImport'
import type { RulesetConfig } from '../domain/configSchema'
import type { DetectionResult } from './workerClient'
import { openResolveReturnFromEmpty } from '../features/resolve-only/resolveReturnController'
import { setCorrelationUiPhase, getCorrelationUiPhase } from '../correlation/correlationPhaseModel'
import { disposeProtocolGraphStateForSession } from '../pcap/sanitize/protocolGraphState.ts'
import { disposeFlowExportCachesForSession } from '../pcap/sanitize/flowExport.ts'

export type {
  SessionKind,
  LifecycleResourceSpec,
  LifecycleResourceId,
} from './sessionLifecycleInventory'

export { LIFECYCLE_RESOURCE_INVENTORY, ZUSTAND_FORBIDDEN_PAYLOADS, isLifecycleTransitionAllowed }

interface LifecycleState {
  kind: SessionKind
  generation: number
  abort: AbortController | null
}

let state: LifecycleState = {
  kind: 'none',
  generation: 0,
  abort: null,
}

function bumpGeneration(): number {
  state.generation += 1
  state.abort?.abort()
  state.abort = new AbortController()
  return state.generation
}

function projectEmptyUi(statusMessage = cs.status.ready): void {
  const store = useAppStore.getState()
  store.resetSession()
  store.setImportProgress({
    ...createIdleProgress(),
    phase: 'idle',
    message: '',
  })
  store.setPhase('empty')
  store.setActiveMode('text')
  store.setStatusMessage(statusMessage)
  store.setLastError(null)
  store.bumpSessionEpoch()
  store.bumpCorrelationEpoch()
}

function beginKind(next: SessionKind): number {
  if (!isLifecycleTransitionAllowed(state.kind, next)) {
    throw new Error(`Lifecycle transition ${state.kind} → ${next} is not allowed`)
  }
  if (requiresExclusiveDispose(state.kind, next) || state.kind !== 'none') {
    // Dispose previous exclusive session before switching kinds.
    if (state.kind !== 'none' && state.kind !== next) {
      disposeActiveSessionInternal({ projectUi: false })
    }
  }
  state.kind = next
  return bumpGeneration()
}

function disposeActiveSessionInternal(opts: { projectUi: boolean; keepStaging?: boolean }): void {
  bumpGeneration()
  abortTextImportWork()
  disposeDetectionClientOnly()
  disposeProtocolGraphStateForSession()
  disposeFlowExportCachesForSession()
  disposeNonTextSessionResources({ keepStaging: opts.keepStaging })
  state.kind = opts.keepStaging ? 'correlation' : 'none'
  if (opts.projectUi) {
    if (opts.keepStaging) {
      setCorrelationUiPhase({ kind: 'staging' })
      useAppStore.getState().setStatusMessage('')
    } else {
      projectEmptyUi()
    }
  }
}

/** Current exclusive session kind (projection authority for ownership). */
export function getActiveSessionKind(): SessionKind {
  return state.kind
}

/** Monotonic generation — late worker callbacks must compare before mutating. */
export function getLifecycleGeneration(): number {
  return state.generation
}

export function isLifecycleGenerationCurrent(token: number): boolean {
  return token === state.generation
}

export function getLifecycleAbortSignal(): AbortSignal | null {
  return state.abort?.signal ?? null
}

/**
 * Cancel the in-flight operation for the active kind and return to a safe idle shell.
 * Idempotent.
 */
export function cancelActiveOperation(): void {
  const appPhase = useAppStore.getState().phase
  const corrKind = getCorrelationUiPhase().kind
  // Initial correlation processing cancel keeps staging (Stage 31 / Stage 5).
  if (appPhase === 'correlation-processing' || corrKind === 'processing') {
    disposeActiveSessionInternal({ projectUi: true, keepStaging: true })
    return
  }
  disposeActiveSessionInternal({ projectUi: true })
  useAppStore.getState().setImportProgress({
    ...createIdleProgress(),
    phase: 'cancelled',
    message: 'Analýza zrušena',
  })
}

/** Dispose active session resources; shell returns to empty. Idempotent. */
export function disposeActiveSession(): void {
  disposeActiveSessionInternal({ projectUi: true })
}

/** Full application reset (ErrorBoundary, new session). Idempotent. */
export function resetApplication(): void {
  disposeActiveSessionInternal({ projectUi: true })
  projectEmptyUi(cs.status.ready)
}

export async function startTextSession(
  input: { readonly file: File } | { readonly text: string },
  profile?: RulesetConfig,
  options?: { resourceConfirmed?: boolean; allowInvalidUtf8?: boolean },
): Promise<DetectionResult> {
  beginKind('text')
  const token = state.generation
  try {
    if ('file' in input) {
      const result = await runFileAnalysis(input.file, profile, options)
      if (!isLifecycleGenerationCurrent(token)) throw new ImportCancelledError()
      state.kind = 'text'
      return result
    }
    const result = await runPasteAnalysis(input.text, profile, options)
    if (!isLifecycleGenerationCurrent(token)) throw new ImportCancelledError()
    state.kind = 'text'
    return result
  } catch (err) {
    if (!isLifecycleGenerationCurrent(token)) throw new ImportCancelledError()
    throw err
  }
}

export async function startPcapSession(
  file: File,
  options?: { replaceConfirmed?: boolean; resourceConfirmed?: boolean },
): Promise<void> {
  beginKind('pcap')
  useAppStore.getState().setActiveMode('pcap')
  const token = state.generation
  const { loadPcapFile } = await import('../pcap/ui/pcapLoadController.ts')
  await loadPcapFile(file, options)
  if (!isLifecycleGenerationCurrent(token)) throw new ImportCancelledError()
  state.kind = 'pcap'
}

/** Open multi-source staging (correlation). Disposes exclusive single-source sessions first. */
export function startCorrelationSession(): void {
  beginKind('correlation')
  setCorrelationUiPhase({ kind: 'staging' })
  useAppStore.getState().setLastError(null)
  useAppStore.getState().bumpCorrelationEpoch()
  state.kind = 'correlation'
}

/**
 * Enter resolve-only mode.
 * - `wizard` (default): empty-state return flow (pick plaintext JSON bundle → lookup).
 * - `imported`: payload already unlocked (e.g. MappingBundleActions import); dispose other
 *   exclusive sessions without clearing that payload.
 */
export function enterResolveOnly(options?: { mode?: 'wizard' | 'imported' }): void {
  if (options?.mode === 'imported') {
    if (!isLifecycleTransitionAllowed(state.kind, 'resolve-only')) {
      throw new Error(`Lifecycle transition ${state.kind} → resolve-only is not allowed`)
    }
    if (state.kind !== 'none' && state.kind !== 'resolve-only') {
      bumpGeneration()
      abortTextImportWork()
      disposeDetectionClientOnly()
      disposeNonTextSessionResources({ keepResolvePayload: true })
    }
    state.kind = 'resolve-only'
    bumpGeneration()
    useAppStore.getState().enterResolveOnly()
    return
  }
  beginKind('resolve-only')
  openResolveReturnFromEmpty()
  state.kind = 'resolve-only'
}

/** Mark kind after an external start that already ran (e.g. route helpers mid-migration). */
export function noteActiveSessionKind(kind: SessionKind): void {
  state.kind = kind
  if (kind !== 'none' && !state.abort) {
    bumpGeneration()
  }
}

export function resetLifecycleCoordinatorForTests(): void {
  state.abort?.abort()
  state = { kind: 'none', generation: 0, abort: null }
}

/** Inventory accessor for docs/tests. */
export function getLifecycleInventory() {
  return LIFECYCLE_RESOURCE_INVENTORY
}
