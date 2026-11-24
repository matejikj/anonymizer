/**
 * Multi-source import orchestration (Stage 27).
 */

import { SourceKind as SK } from '../../domain/sourceArtifact'
import { getActiveProfile } from '../../features/rules/activeProfile'
import { getActivePcapProfile } from '../../pcap/profile/activePcapProfile'
import { useAppStore } from '../../app/store'
import { cs } from '../../i18n/cs.ts'
import { setCorrelationUiPhase } from '../correlationPhaseModel'
import { disposeActiveSession, noteActiveSessionKind } from '../../app/sessionLifecycleCoordinator'
import { ImportCancelledError } from '../../features/import-log/streamImport'
import {
  resolveProfileCompatibilityConflict,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../correlationController'
import {
  applyCategoryResolution,
  compileCorrelationPolicy,
  compatibilityAllowsProcessing,
  evaluateProfileCompatibility,
  sessionPolicyAllowsProcessing,
} from '../profileCompatibility'
import { enterCorrelationFailedPhase, enterCorrelationProcessingPhase, enterCorrelationReviewPhase } from '../correlationWorkspaceController'
import type { CrossFormatCategory } from '../../mapping/crossFormat/types'
import type { ProfileCompatibilityReport, ProfileConflictResolution } from '../profileCompatibility/types'
import type { StagedSourceDescriptor } from '../types'
import {
  buildStagingItemsFromFiles,
  buildStagingSummary,
  clearStagingItems,
  getReadyStagingItems,
  getStagingItems,
  mergeFilesIntoStaging,
  replaceStagingItems,
  stagingDescriptorOutputName,
} from './stagingModel'
import type { ImportRoute } from './types'
import { announceCorrelationSource } from '../correlationLiveAnnouncer.ts'

const stagingResolutions = new Map<CrossFormatCategory, ProfileConflictResolution>()

export function resetCorrelationImportForTests(): void {
  clearStagingItems()
  stagingResolutions.clear()
}

function uniqueSourceKinds(): readonly (typeof SK.Text | typeof SK.Pcap)[] {
  const kinds = new Set<typeof SK.Text | typeof SK.Pcap>()
  for (const item of getReadyStagingItems()) kinds.add(item.kind)
  return [...kinds]
}

function usesTextProfile(kinds: readonly (typeof SK.Text | typeof SK.Pcap)[]): boolean {
  return kinds.includes(SK.Text)
}

export function getStagingProfileCompatibilityReport(): ProfileCompatibilityReport | null {
  const ready = getReadyStagingItems()
  if (ready.length < 2) return null
  const kinds = uniqueSourceKinds()
  const hasTextLike = usesTextProfile(kinds)
  const hasPcap = kinds.includes(SK.Pcap)
  // Effective PCAP policy comes from the active PCAP runtime profile, never from text config.
  if (!hasTextLike || !hasPcap) {
    return evaluateProfileCompatibility(
      compileCorrelationPolicy({
        sourceKinds: kinds,
        textProfile: hasTextLike ? getActiveProfile() : undefined,
        pcapProfile: hasPcap ? getActivePcapProfile() : undefined,
      }),
    )
  }

  let report = evaluateProfileCompatibility(
    compileCorrelationPolicy({
      sourceKinds: kinds,
      textProfile: getActiveProfile(),
      pcapProfile: getActivePcapProfile(),
    }),
  )
  for (const [category, resolution] of stagingResolutions) {
    report = applyCategoryResolution(report, category, resolution)
  }
  return report
}

export function resolveStagingProfileConflict(
  category: CrossFormatCategory,
  resolution: ProfileConflictResolution,
): ProfileCompatibilityReport | null {
  stagingResolutions.set(category, resolution)
  useAppStore.getState().bumpCorrelationEpoch()
  return getStagingProfileCompatibilityReport()
}

export function applyRecommendedStagingResolutions(): ProfileCompatibilityReport | null {
  const report = getStagingProfileCompatibilityReport()
  if (!report) return null
  for (const conflict of report.unresolved) {
    stagingResolutions.set(conflict.category, conflict.recommended)
  }
  useAppStore.getState().bumpCorrelationEpoch()
  return getStagingProfileCompatibilityReport()
}

export function canConfirmCorrelationStaging(): boolean {
  return getStagingConfirmBlockedReason() == null
}

/** Visible reason why analysis is disabled; one ready file is sufficient. */
export function getStagingConfirmBlockedReason(): string | null {
  const summary = buildStagingSummary()
  if (summary.readyCount === 0) {
    return cs.correlationStaging.blockedNoReady
  }
  if (summary.aggregateOverLimit) {
    return cs.correlationStaging.blockedAggregateLimit
  }
  const report = getStagingProfileCompatibilityReport()
  if (report && !compatibilityAllowsProcessing(report)) {
    return cs.correlationStaging.blockedCompatibility
  }
  return null
}

function bumpStagingView(): void {
  useAppStore.getState().bumpCorrelationEpoch()
}

export function openCorrelationStaging(): void {
  noteActiveSessionKind('correlation')
  setCorrelationUiPhase({ kind: 'staging' })
  useAppStore.getState().setLastError(null)
  bumpStagingView()
}

export async function ingestDroppedFiles(files: readonly File[]): Promise<ImportRoute> {
  if (files.length === 0) return { kind: 'nothing' }

  useAppStore.getState().setStatusMessage(cs.inputRejection.inflatingProgress)
  let items
  try {
    items = await buildStagingItemsFromFiles(files)
  } finally {
    useAppStore.getState().setStatusMessage('')
  }

  const readyOrDup = items.filter((i) => i.status === 'ready' || i.status === 'duplicate-warning')
  // T73 — one dropped file auto-split into segments → correlation staging (shared mapping).
  if (files.length === 1 && readyOrDup.length === 1) {
    const only = readyOrDup[0]!
    if (only.kind === SK.Text) return { kind: 'single-text', file: only.file }
    if (only.kind === SK.Pcap) return { kind: 'single-pcap', file: only.file }
  }

  if (readyOrDup.length === 0) {
    replaceStagingItems(items)
    return { kind: 'nothing' }
  }

  replaceStagingItems(items)
  stagingResolutions.clear()
  return { kind: 'staging', summary: buildStagingSummary(items) }
}

export async function routeSingleTextFile(file: File): Promise<void> {
  const { startTextSession } = await import('../../app/sessionLifecycleCoordinator.ts')
  useAppStore.getState().setActiveMode('text')
  useAppStore.getState().setLastError(null)
  await startTextSession({ file })
}

export async function routeSinglePcapFile(file: File): Promise<void> {
  const { startPcapSession } = await import('../../app/sessionLifecycleCoordinator.ts')
  useAppStore.getState().setLastError(null)
  useAppStore.getState().setActiveMode('pcap')
  await startPcapSession(file)
}

export async function handleUniversalFileDrop(files: readonly File[]): Promise<void> {
  const route = await ingestDroppedFiles(files)
  switch (route.kind) {
    case 'nothing': {
      const err = getStagingItems().find((i) => i.status === 'error')
      if (err && err.status === 'error') {
        useAppStore.getState().setLastError(err.message)
        announceCorrelationSource(err.message)
      }
      clearStagingItems()
      return
    }
    case 'single-text':
      try {
        await routeSingleTextFile(route.file)
      } catch (err) {
        if (err instanceof ImportCancelledError) return
        const message = err instanceof Error ? err.message : String(err)
        useAppStore.getState().setLastError(message)
        useAppStore.getState().setPhase('empty')
      }
      return
    case 'single-pcap':
      try {
        await routeSinglePcapFile(route.file)
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        useAppStore.getState().setLastError(message)
        useAppStore.getState().setPhase('empty')
      }
      return
    case 'staging': {
      const { startCorrelationSession } = await import('../../app/sessionLifecycleCoordinator.ts')
      startCorrelationSession()
      return
    }
    default:
      return
  }
}

export async function addMoreStagingFiles(files: readonly File[]): Promise<void> {
  stagingResolutions.clear()
  await mergeFilesIntoStaging(files)
  bumpStagingView()
}

export function leaveCorrelationStaging(): void {
  disposeActiveSession()
}

function buildDescriptors(): StagedSourceDescriptor[] {
  return getReadyStagingItems().map((item) => ({
    sourceId: item.id,
    kind: item.kind,
    file: item.file,
    outputFileName: stagingDescriptorOutputName(item),
    inputKind: 'file' as const,
    split: item.split,
  }))
}

export async function confirmCorrelationStaging(): Promise<
  { ok: true; sourceCount: number; mode: 'single' | 'correlation' } | { ok: false; message: string; cancelled?: boolean }
> {
  const blockedReason = getStagingConfirmBlockedReason()
  if (blockedReason) {
    return { ok: false, message: blockedReason }
  }
  if (getReadyStagingItems().length === 1) {
    const result = await continueCorrelationStagingWithSingleFile()
    return result.ok ? { ok: true, sourceCount: 1, mode: 'single' } : result
  }

  const resolutions = [...stagingResolutions.entries()].map(([category, resolution]) => ({
    category,
    resolution,
  }))

  const result = await startCorrelationProcessingFromStaging(resolutions)
  return result.ok ? { ...result, mode: 'correlation' } : result
}

async function startCorrelationProcessingFromStaging(
  applyResolutions: readonly { category: CrossFormatCategory; resolution: ProfileConflictResolution }[],
): Promise<{ ok: true; sourceCount: number } | { ok: false; message: string; cancelled?: boolean }> {
  const descriptors = buildDescriptors()
  const staged = await stageCorrelationDescriptors(descriptors)
  if (!('ok' in staged) || !staged.ok) {
    return { ok: false, message: 'message' in staged ? staged.message : 'Staging selhalo.' }
  }

  for (const item of applyResolutions) {
    resolveProfileCompatibilityConflict(item.category, item.resolution)
  }

  if (!sessionPolicyAllowsProcessing()) {
    return { ok: false, message: 'Profilový konflikt blokuje společnou anonymizaci.' }
  }

  enterCorrelationProcessingPhase()
  const processed = await runCorrelationSession()
  if (!('ok' in processed) || !processed.ok) {
    if ('code' in processed && processed.code === 'correlation-cancelled') {
      return { ok: false, message: processed.message, cancelled: true }
    }
    // Pause on progress UI — do not wipe staging or jump away (Stage 31).
    enterCorrelationFailedPhase('staging')
    return { ok: false, message: 'message' in processed ? processed.message : 'Analýza selhala.' }
  }

  enterCorrelationReviewPhase()
  return { ok: true, sourceCount: processed.sourceCount }
}

export async function continueCorrelationStagingWithSingleFile(): Promise<
  { ok: true } | { ok: false; message: string }
> {
  const ready = getReadyStagingItems()
  if (ready.length !== 1) {
    return { ok: false, message: cs.correlationStaging.singleContinueFailed }
  }
  const only = ready[0]!
  const file = only.file
  clearStagingItems()
  stagingResolutions.clear()
  bumpStagingView()

  try {
    if (only.kind === SK.Text) {
      await routeSingleTextFile(file)
      return { ok: true }
    }
    if (only.kind === SK.Pcap) {
      await routeSinglePcapFile(file)
      return { ok: true }
    }
    return { ok: false, message: cs.correlationStaging.singleContinueFailed }
  } catch (err) {
    if (err instanceof ImportCancelledError) {
      return { ok: false, message: cs.correlationStaging.singleContinueFailed }
    }
    const message = err instanceof Error ? err.message : cs.correlationStaging.singleContinueFailed
    useAppStore.getState().setLastError(message)
    useAppStore.getState().setPhase('empty')
    return { ok: false, message }
  }
}

export function singleFileStagingErrorMessage(): string | null {
  const err = getStagingItems().find((i) => i.status === 'error')
  return err && err.status === 'error' ? err.message : null
}

/** Supported file extensions for universal multi-source picker. */
export const UNIVERSAL_FILE_ACCEPT =
  '.log,.txt,.pcap,.pcapng,.cap,.gz,.xz,.zst,.zstd,.bz2,.zip,.tar,.tgz,.tar.gz,.tar.xz,.txz,.tar.bz2,.tbz2,.tar.zst,.tzst,text/*,application/gzip,application/x-xz,application/zstd,application/x-bzip2,application/zip,application/x-tar,application/octet-stream'
