/**
 * Session analysis controller — generation ID, Worker client, cancel (ARCHITECTURE §8 / §9.1).
 * Large buffers stay outside Zustand; store only holds progress summaries.
 */

import type { RulesetConfig } from '../domain/configSchema.ts'
import {
  DetectionWorkerClient,
  type DetectionResult,
  type WorkerClientStatus,
} from './workerClient.ts'
import {
  importFileAndDetect,
  importPasteAndDetect,
  ImportCancelledError,
} from '../features/import-log/streamImport.ts'
import type { ImportProgress } from '../features/import-log/importProgress.ts'
import { createIdleProgress, phaseMessage } from '../features/import-log/importProgress.ts'
import {
  preflightFile,
  preflightPaste,
  type LogMode,
  type PreflightOk,
} from '../features/import-log/preflight.ts'
import { buildSessionModel, clearSessionModel, getSessionModel } from '../features/workspace/sessionModel.ts'
import { useAppStore } from './store.ts'
import { utf8ByteLength } from '../features/import-log/streamingDecode.ts'
import { getActiveProfile } from '../features/rules/activeProfile.ts'
import { applyEffectiveMatchFlags } from '../features/review/entityState.ts'
import { buildReplacementPlan } from '../engine/transform.ts'
import type { CategoryMasterMap } from '../features/review/entityState.ts'
import { getDualLogBridge } from '../features/workspace/editorBridge.ts'
import {
  detectResourceConflict,
  releasePcapSessionForText,
} from '../pcap/ui/pcapResourceCoordinator.ts'
import { promptResourceConflict } from './resourceConflictPrompt.ts'
import { disposeNonTextSessionResources } from './sessionLifecycleDispose.ts'

let client: DetectionWorkerClient | null = null
let abort: AbortController | null = null
/** Last detection result buffers — held outside React state. */
let lastDetection: DetectionResult | null = null
let lastText: string | null = null
/** Packed original line endings for export (parallel to physical lines). */
let lastLineEndings: Uint8Array | null = null

function getClient(): DetectionWorkerClient {
  if (!client) {
    client = new DetectionWorkerClient({
      onStatus(status: WorkerClientStatus) {
        useAppStore.getState().setWorkerStatus(status)
      },
      onProgress(ev) {
        useAppStore.getState().patchImportProgress({
          processedBytes: ev.processedBytes,
          processedLines: ev.processedLines,
          phase: 'analyzing',
          message: phaseMessage('analyzing'),
        })
      },
    })
  }
  return client
}

/** Shared worker client for post-detection plan rebuilds (Krok 6). */
export function getClientForReview(): DetectionWorkerClient {
  return getClient()
}

export function getLastDetection(): DetectionResult | null {
  return lastDetection
}

export function getLastImportedText(): string | null {
  return lastText
}

/** Abort in-flight text import/detection only (Stage 5 — no cross-domain releases). */
export function abortTextImportWork(): void {
  abort?.abort()
  abort = null
  try {
    getClient().cancel()
  } catch {
    /* worker may already be gone */
  }
  lastDetection = null
  lastText = null
  lastLineEndings = null
  clearSessionModel()
}

/** Dispose detection worker client without touching other session kinds. */
export function disposeDetectionClientOnly(): void {
  abort?.abort()
  abort = null
  client?.dispose()
  client = null
}

/**
 * Cancel text analysis and return to empty.
 * Prefer `cancelActiveOperation()` from SessionLifecycleCoordinator for full cleanup;
 * this remains for backward-compatible call sites and delegates cross-domain dispose.
 */
export function cancelAnalysis(): void {
  abortTextImportWork()
  disposeNonTextSessionResources()
  useAppStore.getState().setImportProgress({
    ...createIdleProgress(),
    phase: 'cancelled',
    message: 'Analýza zrušena',
  })
  useAppStore.getState().bumpSessionEpoch()
  useAppStore.getState().setPhase('empty')
}

function releasePreviousSession(): void {
  // ARCHITECTURE §3.1 / §8: never hold two large logs; release via Stage 5 dispose order.
  disposeNonTextSessionResources()
  lastDetection = null
  lastText = null
  lastLineEndings = null
  clearSessionModel()
}

async function ensureTextResourceClear(
  incomingBytes: number,
  resourceConfirmed?: boolean,
): Promise<boolean> {
  const conflict = detectResourceConflict('text', incomingBytes)
  if (!conflict) return true
  if (resourceConfirmed) {
    releasePcapSessionForText()
    return true
  }
  const ok = await promptResourceConflict(conflict)
  if (!ok) return false
  releasePcapSessionForText()
  return true
}

function finishSession(input: {
  text: string
  lineEndings: Uint8Array
  detection: DetectionResult
  fileName: string | null
  byteLength: number
  mode: LogMode
}): DetectionResult {
  lastDetection = input.detection
  lastText = input.text
  lastLineEndings = input.lineEndings
  buildSessionModel({
    text: input.text,
    detection: input.detection,
    fileName: input.fileName,
    byteLength: input.byteLength,
    mode: input.mode,
    workerPlanTrusted: true,
    lineEndings: input.lineEndings,
  })
  const store = useAppStore.getState()
  store.bumpSessionEpoch()
  store.setOccurrenceIndex(-1)
  store.setFocusedLine(1)
  store.setGeneration(input.detection.requestId)
  store.setImportProgress({
    ...createIdleProgress(),
    phase: 'done',
    requestId: input.detection.requestId,
    processedBytes: input.byteLength,
    processedLines: input.detection.lineCount,
    message: phaseMessage('done'),
    failedRuleIds: input.detection.failedRuleIds,
  })
  store.setPhase('workspace')
  store.setStatusMessage(
    `Hotovo · ${input.detection.entities.length} hodnot · ${input.detection.lineCount.toLocaleString('cs-CZ')} řádků`,
  )
  return input.detection
}

export async function runPasteAnalysis(
  text: string,
  profile: RulesetConfig = getActiveProfile(),
  options: { resourceConfirmed?: boolean } = {},
): Promise<DetectionResult> {
  const store = useAppStore.getState()
  store.setActiveMode('text')
  store.setLastError(null)
  store.setImportProgress({
    ...createIdleProgress(),
    phase: 'checking',
    message: phaseMessage('checking'),
    startedAt: Date.now(),
    fileName: null,
  })
  store.setPhase('importing')

  const pre = preflightPaste(text)
  if (!pre.ok) {
    store.setLastError(pre.message)
    store.setPhase('empty')
    throw new Error(pre.message)
  }

  const resourceOk = await ensureTextResourceClear(pre.byteLength, options.resourceConfirmed)
  if (!resourceOk) {
    store.setPhase(getSessionModel() ? 'workspace' : 'empty')
    throw new ImportCancelledError()
  }

  store.patchImportProgress({ totalBytes: pre.byteLength })

  releasePreviousSession()
  abort?.abort()
  abort = new AbortController()

  try {
    const result = await importPasteAndDetect(text, getClient(), {
      profile,
      signal: abort.signal,
      handlers: {
        onProgress: (p: ImportProgress) => store.setImportProgress(p),
      },
    })
    return finishSession({
      text: result.text,
      lineEndings: result.lineEndings,
      detection: result.detection,
      fileName: null,
      byteLength: pre.byteLength,
      mode: pre.mode,
    })
  } catch (err) {
    handleImportError(err)
    throw err
  }
}

export async function runFileAnalysis(
  file: File,
  profile: RulesetConfig = getActiveProfile(),
  options: { allowInvalidUtf8?: boolean; resourceConfirmed?: boolean } = {},
): Promise<DetectionResult> {
  const store = useAppStore.getState()
  store.setActiveMode('text')
  store.setLastError(null)
  store.setImportProgress({
    ...createIdleProgress(),
    phase: 'checking',
    message: phaseMessage('checking'),
    totalBytes: file.size,
    startedAt: Date.now(),
    fileName: file.name,
  })
  store.setPhase('importing')

  abort?.abort()
  abort = new AbortController()

  let pre: PreflightOk
  try {
    const encodingOverride = store.textEncodingOverride ?? undefined
    const result = await preflightFile(file, {
      signal: abort.signal,
      encoding: encodingOverride,
    })
    if (!result.ok) {
      store.setLastError(result.message)
      store.setPhase('empty')
      throw new Error(result.message)
    }
    pre = result
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      store.setPhase('empty')
      throw new ImportCancelledError()
    }
    throw err
  }

  if (pre.hadInvalidUtf8 && !options.allowInvalidUtf8) {
    store.setPhase('empty')
    const err = Object.assign(new Error('INVALID_UTF8'), {
      code: 'invalid-utf8' as const,
      preflight: pre,
    })
    throw err
  }

  const resourceOk = await ensureTextResourceClear(pre.byteLength, options.resourceConfirmed)
  if (!resourceOk) {
    store.setPhase(getSessionModel() ? 'workspace' : 'empty')
    throw new ImportCancelledError()
  }

  releasePreviousSession()

  try {
    const result = await importFileAndDetect(file, getClient(), {
      profile,
      signal: abort.signal,
      encoding: pre.sourceEncoding,
      handlers: {
        onProgress: (p: ImportProgress) => store.setImportProgress(p),
      },
    })
    store.setTextSourceMeta({
      sourceEncoding: result.sourceEncoding,
      outputEncoding: result.outputEncoding,
      encodingConfidence: pre.encodingConfidence,
      structuredFormat: result.structuredStats?.format,
    })
    return finishSession({
      text: result.text,
      lineEndings: result.lineEndings,
      detection: result.detection,
      fileName: file.name,
      byteLength: pre.byteLength,
      mode: pre.mode,
    })
  } catch (err) {
    handleImportError(err)
    throw err
  }
}

function handleImportError(err: unknown): void {
  const store = useAppStore.getState()
  clearSessionModel()
  lastDetection = null
  lastText = null
  lastLineEndings = null
  if (err instanceof ImportCancelledError) {
    store.setPhase('empty')
    return
  }
  const message = err instanceof Error ? err.message : String(err)
  if (message !== 'INVALID_UTF8') store.setLastError(message)
  store.setPhase('empty')
}

export function disposeSessionController(): void {
  disposeDetectionClientOnly()
  lastDetection = null
  lastText = null
  lastLineEndings = null
  clearSessionModel()
}

/**
 * Re-run detection on the current canonical log text with the active ruleset.
 */
export async function reanalyzeWithActiveProfile(): Promise<DetectionResult> {
  const text = lastText ?? getSessionModel()?.original
  if (!text) {
    throw new Error('Žádný načtený log pro opětovnou analýzu')
  }
  const prev = getSessionModel()
  const fileName = prev?.meta.fileName ?? null
  const mode = prev?.meta.mode ?? 'common'
  const byteLength = prev?.meta.byteLength ?? utf8ByteLength(text)
  const preservedMasters: CategoryMasterMap | undefined = prev?.categoryMasters
    ? { ...prev.categoryMasters }
    : undefined
  const preservedLineEndings = lastLineEndings ?? prev?.lineEndings
  const profile = getActiveProfile()

  const store = useAppStore.getState()
  store.setLastError(null)
  store.setPlanBusy(true)
  store.setStatusMessage('Analyzuji…')
  store.setImportProgress({
    ...createIdleProgress(),
    phase: 'analyzing',
    message: phaseMessage('analyzing'),
    totalBytes: byteLength,
  })
  // Keep workspace mounted so the rules form / review panel stay interactive.

  abort?.abort()
  abort = new AbortController()

  try {
    const result = await importPasteAndDetect(text, getClient(), {
      profile,
      signal: abort.signal,
      handlers: {
        onProgress: (p: ImportProgress) => store.setImportProgress(p),
      },
    })
    const detection = finishSession({
      text: result.text,
      lineEndings: preservedLineEndings ?? result.lineEndings,
      detection: result.detection,
      fileName,
      byteLength,
      mode,
    })
    const session = getSessionModel()
    if (session && preservedMasters) {
      session.categoryMasters = preservedMasters
      applyEffectiveMatchFlags(session.packed, session.entities, session.categoryMasters)
      session.plan = buildReplacementPlan(session.packed, session.entities)
      session.planRevision += 1
      store.bumpSessionEpoch()
    }
    getDualLogBridge()?.refreshDecorations()
    return detection
  } catch (err) {
    if (getSessionModel()) {
      store.setPhase('workspace')
      store.setStatusMessage(csReanalyzeFailed())
    } else {
      handleImportError(err)
    }
    throw err
  } finally {
    store.setPlanBusy(false)
  }
}

function csReanalyzeFailed(): string {
  return 'Opětovná analýza se nezdařila — předchozí náhled zůstal zachován.'
}

export { getSessionModel, utf8ByteLength }
