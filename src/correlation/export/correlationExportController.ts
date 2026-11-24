/**
 * Multi-source correlation export orchestration (Stage 29 / MIXED step 3).
 */

import { SourceKind as SK } from '../../domain/sourceArtifact'
import { getSharedMappingClient } from '../../mapping/sharedMappingClient'
import {
  downloadBlob,
  ExportCancelledError,
} from '../../features/export-log/exportCoordinator'
import {
  BlobExportSink,
  createDirectoryFileSink,
  pickExportDirectory,
  supportsDirectoryPicker,
  triggerBlobDownload,
  writeTextToDirectory,
  type ExportSink,
} from '../../pcap/export/sinks'
import { buildSupportBundleOutputZip } from '../archive/supportBundle.ts'
import { getLastSupportBundleMeta } from '../import/stagingModel.ts'
import { fileFingerprint } from '../import/sourcePreflightPort.ts'

export const SUPPORT_BUNDLE_OUTPUT_ZIP_NAME = 'support-bundle.anonym.zip'
import { PcapExportCancelledError } from '../../pcap/export/coordinator'
import {
  getCorrelationSessionModel,
  listCorrelationSources,
} from '../correlationSessionModel'
import type { CorrelationSourceRecord } from '../types'
import { exportTextSourcePlan, loadTextFileForExport } from './textSourceExportPort'
import {
  assessCorrelationSourceExport,
  correlationSourceExposedHint,
} from './correlationExportSecurity'
import {
  assertShareableManifestHasNoLeaks,
  buildShareableCorrelationManifest,
  needsShareableCorrelationManifest,
  SHAREABLE_MANIFEST_FILE_NAME,
} from './correlationShareManifest'
import { allocateUniqueOutputNames } from './uniqueOutputNames'
import type {
  CorrelationExportFileItem,
  CorrelationExportOutcome,
  CorrelationExportPreview,
  CorrelationExportScope,
  CorrelationExportSkipReason,
} from './correlationExportTypes'
import {
  markCorrelationExportComplete,
  setCorrelationExportProgress,
} from './correlationExportModel'
import { exportPcapSourcePlan } from './pcapSourceExportPort'
import { useAppStore } from '../../app/store'
import { isExportBlockedBySessionPolicy } from '../profileCompatibility/sessionPolicy'
import { cs } from '../../i18n/cs'

export class CorrelationExportCancelledError extends Error {
  constructor() {
    super('Correlation export cancelled')
    this.name = 'CorrelationExportCancelledError'
  }
}

export interface BuildExportPreviewOptions {
  readonly scope?: CorrelationExportScope
  readonly currentSourceId?: string | null
  /** When set, reject if session generation/revision drifted (drawer reopen check). */
  readonly expectedGenerationId?: string | null
  readonly expectedMappingRevision?: number | null
}

function skipDetailFor(record: CorrelationSourceRecord, reason: CorrelationExportSkipReason): string | null {
  if (reason === 'failed') {
    return record.errorMessage?.trim() || cs.correlationExport.skipFailed
  }
  if (reason === 'not-planned') return cs.correlationExport.skipNotPlanned
  if (reason === 'pending') return cs.correlationExport.skipPending
  if (reason === 'blocked') return cs.correlationExport.blockedHint
  if (reason === 'rebuilding') return cs.correlationExport.skipRebuilding
  return null
}

function buildFileItem(
  record: CorrelationSourceRecord,
  outputFileName: string,
): CorrelationExportFileItem {
  const rebuilding = useAppStore.getState().planBusy || isExportBlockedBySessionPolicy()
  let security: CorrelationExportFileItem['security'] = 'blocked'
  let exportable = false
  let skipReason: CorrelationExportSkipReason = 'blocked'
  let exposedHint: string | null = null

  if (rebuilding) {
    skipReason = 'rebuilding'
  } else if (record.phase === 'failed') {
    skipReason = 'failed'
  } else if (record.phase === 'staged' || record.phase === 'discovering' || record.phase === 'resolved') {
    skipReason = record.phase === 'staged' ? 'pending' : 'not-planned'
  } else if (record.phase !== 'planned') {
    skipReason = 'not-planned'
  } else {
    const assessed = assessCorrelationSourceExport({
      ...record,
      exportState: record.exportState === 'blocked' ? 'blocked' : 'ready',
    })
    security = assessed
    exposedHint = correlationSourceExposedHint(record, assessed)
    if (assessed === 'blocked' || record.exportState === 'blocked') {
      skipReason = 'blocked'
      security = 'blocked'
    } else {
      exportable = true
      skipReason = null
    }
  }

  return {
    sourceId: record.sourceId,
    inputFileName: record.fileName,
    outputFileName,
    kind: record.kind,
    security,
    exportable,
    exposedHint,
    skipReason,
    skipDetail: skipDetailFor(record, skipReason),
    artifactKind: 'data',
  }
}

function resolveScopeSourceIds(
  scope: CorrelationExportScope,
  currentSourceId: string | null | undefined,
): { sourceIds: string[]; canChooseCurrent: boolean } {
  const all = listCorrelationSources()
  const canChooseCurrent = Boolean(currentSourceId && currentSourceId !== 'all')
  if (scope === 'current' && canChooseCurrent && currentSourceId) {
    return { sourceIds: [currentSourceId], canChooseCurrent }
  }
  return { sourceIds: all.map((s) => s.sourceId), canChooseCurrent }
}

export function buildCorrelationExportPreview(
  sourceIdsOrOptions?: readonly string[] | BuildExportPreviewOptions,
): CorrelationExportPreview {
  const legacyIds = Array.isArray(sourceIdsOrOptions) ? [...sourceIdsOrOptions] : null
  const options: BuildExportPreviewOptions =
    legacyIds !== null ? { scope: 'set' } : ((sourceIdsOrOptions as BuildExportPreviewOptions | undefined) ?? {})

  const scope = options.scope ?? 'set'
  const { sourceIds: scopedIds, canChooseCurrent } = legacyIds
    ? { sourceIds: legacyIds, canChooseCurrent: false }
    : resolveScopeSourceIds(scope, options.currentSourceId)

  const model = getCorrelationSessionModel()
  const generationId = model?.generationId ?? null
  const mappingRevision = model?.mappingRevision ?? getSharedMappingClient().getPublishedRevision()

  const selected = listCorrelationSources().filter((s) => scopedIds.includes(s.sourceId))
  // Preserve set order; include every selected source even when not planned.
  const ordered = scopedIds
    .map((id) => selected.find((s) => s.sourceId === id))
    .filter((s): s is CorrelationSourceRecord => Boolean(s))

  const uniqueNames = allocateUniqueOutputNames(
    ordered.map((r) => ({ sourceId: r.sourceId, outputFileName: r.outputFileName })),
  )

  const files = ordered.map((r) => buildFileItem(r, uniqueNames.get(r.sourceId) ?? r.outputFileName))
  const exportable = files.filter((f) => f.exportable)
  const blockedCount = files.filter((f) => f.security === 'blocked' || !f.exportable).length
  const skippedCount = files.filter((f) => !f.exportable).length
  const exposedCount = files.filter((f) => f.security === 'exposed' && f.exportable).length
  const snapshot = getSharedMappingClient().getPublishedSnapshot()
  const includeManifest =
    exportable.length > 0 && snapshot ? needsShareableCorrelationManifest(snapshot) : false
  const blockedInSelection = skippedCount > 0
  const partialOnly = blockedInSelection && exportable.length > 0

  return {
    scope: legacyIds ? 'set' : scope,
    files,
    exportableCount: exportable.length,
    blockedCount,
    skippedCount,
    exposedCount,
    includeManifest,
    manifestFileName: SHAREABLE_MANIFEST_FILE_NAME,
    canExportAll: exportable.length > 0 && !blockedInSelection,
    partialOnly,
    dataFileCount: exportable.length,
    companionFileCount: includeManifest ? 1 : 0,
    generationId,
    mappingRevision,
    sourceIds: ordered.map((r) => r.sourceId),
    canChooseCurrent,
  }
}

export function isExportPreviewStale(preview: CorrelationExportPreview): boolean {
  const model = getCorrelationSessionModel()
  if (!model) return true
  if (preview.generationId && preview.generationId !== model.generationId) return true
  const rev = model.mappingRevision ?? getSharedMappingClient().getPublishedRevision()
  if (preview.mappingRevision != null && preview.mappingRevision !== rev) return true
  if (useAppStore.getState().planBusy || isExportBlockedBySessionPolicy()) return true
  return false
}

export function correlationSetIsUnstableForExport(): boolean {
  if (useAppStore.getState().planBusy) return true
  if (isExportBlockedBySessionPolicy()) return true
  return false
}

async function deliverBlob(
  fileName: string,
  blob: Blob,
  directory: FileSystemDirectoryHandle | null,
): Promise<'directory' | 'download'> {
  if (directory) {
    const sink = await createDirectoryFileSink(directory, fileName)
    const buffer = await blob.arrayBuffer()
    await sink.write(buffer)
    await sink.finalize()
    return 'directory'
  }
  triggerBlobDownload(blob, fileName)
  return 'download'
}

async function exportOneSource(
  record: CorrelationSourceRecord,
  outputFileName: string,
  directory: FileSystemDirectoryHandle | null,
  signal: AbortSignal,
  onFileProgress: (message: string) => void,
  /** When true, keep anonymized bytes for support-bundle ZIP packing (T44). */
  retainBytes: boolean,
): Promise<{
  fileName: string
  byteLength: number
  delivery: 'directory' | 'download'
  bytes: Uint8Array | null
}> {
  if (signal.aborted) throw new CorrelationExportCancelledError()
  const { assertSourcePlanInvariant } = await import('./sourcePlanInvariant')
  assertSourcePlanInvariant(record)

  if (record.kind === SK.Text && record.plan?.kind === 'text' && record.discovery?.kind === 'text') {
    const materialized = await loadTextFileForExport(record.file)
    onFileProgress('Transformuji text…')
    const result = await exportTextSourcePlan({
      plan: { ...record.plan, outputFileName },
      discovery: record.discovery,
      original: materialized.text,
      outputFileName,
      signal,
      forceMainThread: true,
      onProgress: (p) => onFileProgress(p.message),
    })
    const delivery = await deliverBlob(result.fileName, result.blob, directory)
    const bytes = retainBytes ? new Uint8Array(await result.blob.arrayBuffer()) : null
    return { fileName: result.fileName, byteLength: result.byteLength, delivery, bytes }
  }

  if (record.kind === SK.Pcap && record.plan?.kind === 'pcap' && record.discovery?.kind === 'pcap') {
    // Always blob sink when packing support bundle (need bytes) or when downloading.
    const useBlobSink = retainBytes || !directory
    let sink: ExportSink
    if (useBlobSink) {
      sink = new BlobExportSink(outputFileName)
    } else {
      sink = await createDirectoryFileSink(directory!, outputFileName)
    }
    onFileProgress('Přepisuji capture…')
    const result = await exportPcapSourcePlan({
      plan: { ...record.plan, outputFileName },
      discovery: record.discovery,
      sourceBlob: record.file,
      outputFileName,
      sink,
      skipAutoDownload: true,
      onProgress: (p) => onFileProgress(p.message),
    })
    if (useBlobSink && result.blob) {
      const delivery = await deliverBlob(result.fileName, result.blob, directory)
      const bytes = retainBytes ? new Uint8Array(await result.blob.arrayBuffer()) : null
      return { fileName: result.fileName, byteLength: result.byteLength, delivery, bytes }
    }
    return {
      fileName: result.fileName,
      byteLength: result.byteLength,
      delivery: 'directory',
      bytes: null,
    }
  }

  if (record.plan?.kind === 'test') {
    const body = record.plan.signature
    const blob = new Blob([body], { type: 'text/plain;charset=utf-8' })
    const delivery = await deliverBlob(outputFileName, blob, directory)
    const bytes = retainBytes ? new TextEncoder().encode(body) : null
    return { fileName: outputFileName, byteLength: blob.size, delivery, bytes }
  }

  throw new Error(`Source ${record.sourceId} is not exportable`)
}

let activeExportAbort: AbortController | null = null
/** Frozen records for the in-flight export — UI must not mutate this set mid-run. */
let frozenExportRecords: readonly CorrelationSourceRecord[] | null = null

export function cancelCorrelationExport(): void {
  activeExportAbort?.abort()
}

export function getFrozenCorrelationExportRecords(): readonly CorrelationSourceRecord[] | null {
  return frozenExportRecords
}

export async function runCorrelationExport(input: {
  sourceIds?: readonly string[]
  scope?: CorrelationExportScope
  currentSourceId?: string | null
  partial?: boolean
  signal?: AbortSignal
  /** When true, open directory picker first (Chrome/Edge). Default false = browser download like single-file. */
  preferDirectoryPicker?: boolean
  /** Snapshot from drawer open — reject if session drifted. */
  expectedGenerationId?: string | null
  expectedMappingRevision?: number | null
}): Promise<CorrelationExportOutcome> {
  if (correlationSetIsUnstableForExport()) {
    return {
      ok: false,
      code: 'unstable',
      message: cs.correlationExport.unstableSet,
      completedFiles: [],
      remainingFiles: [],
    }
  }

  const ac = new AbortController()
  activeExportAbort = ac
  const signal = input.signal ?? ac.signal

  const preview = input.sourceIds
    ? buildCorrelationExportPreview(input.sourceIds)
    : buildCorrelationExportPreview({
        scope: input.scope ?? 'set',
        currentSourceId: input.currentSourceId,
      })

  if (
    (input.expectedGenerationId != null && preview.generationId !== input.expectedGenerationId) ||
    (input.expectedMappingRevision != null && preview.mappingRevision !== input.expectedMappingRevision)
  ) {
    return {
      ok: false,
      code: 'stale',
      message: cs.correlationExport.stalePreview,
      completedFiles: [],
      remainingFiles: [],
    }
  }

  const exportableItems = preview.files.filter((f) => f.exportable)
  if (exportableItems.length === 0) {
    return {
      ok: false,
      code: 'empty',
      message: cs.correlationExport.emptyExport,
      completedFiles: [],
      remainingFiles: [],
    }
  }

  if (!input.partial && preview.skippedCount > 0) {
    return {
      ok: false,
      code: 'blocked',
      message: cs.correlationExport.blockedInSelection,
      completedFiles: [],
      remainingFiles: [],
    }
  }

  // Freeze source records + plans at start so UI toggles cannot alter the run.
  const live = listCorrelationSources()
  const records = exportableItems
    .map((item) => {
      const liveRecord = live.find((s) => s.sourceId === item.sourceId)
      if (!liveRecord || liveRecord.exportState !== 'ready' || liveRecord.phase !== 'planned') return null
      return {
        ...liveRecord,
        outputFileName: item.outputFileName,
      }
    })
    .filter((r): r is CorrelationSourceRecord => Boolean(r))

  frozenExportRecords = records

  const skippedFiles = preview.files.filter((f) => !f.exportable)
  const manifestNeeded = preview.includeManifest
  const bundleMeta = getLastSupportBundleMeta()
  const exportScope = input.scope ?? 'set'
  const packSupportBundle = bundleMeta != null && exportScope === 'set'
  const plannedFiles = [
    ...records.map((r) => r.outputFileName),
    ...(manifestNeeded ? [SHAREABLE_MANIFEST_FILE_NAME] : []),
    ...(packSupportBundle ? [SUPPORT_BUNDLE_OUTPUT_ZIP_NAME] : []),
  ]
  const remainingOf = (done: readonly string[]) => plannedFiles.filter((n) => !done.includes(n))
  const fileTotal = plannedFiles.length
  const completedFiles: string[] = []
  const dataFiles: string[] = []
  const companionFiles: string[] = []
  let usedDirectoryPicker = false
  let usedMultiDownloadFallback = false
  let downloadUnverified = false

  setCorrelationExportProgress({
    phase: 'picking-directory',
    fileIndex: 0,
    fileTotal,
    currentFileName: '',
    currentMessage: cs.correlationExport.preparing,
    completedFiles: [],
    remainingFiles: [...plannedFiles],
    usedDirectoryPicker: false,
    usedMultiDownloadFallback: false,
    downloadUnverified: false,
  })

  let directory: FileSystemDirectoryHandle | null = null
  // Skip directory picker unless explicitly requested — default matches single-file
  // text/PCAP export (browser download to Stažené / Downloads).
  if (input.preferDirectoryPicker === true && supportsDirectoryPicker()) {
    directory = await pickExportDirectory()
    if (directory) usedDirectoryPicker = true
  }
  if (!directory) {
    usedMultiDownloadFallback = true
    downloadUnverified = true
  }

  if (signal.aborted) {
    const remainingFiles = remainingOf(completedFiles)
    setCorrelationExportProgress({
      phase: 'cancelled',
      completedFiles: [...completedFiles],
      remainingFiles,
      currentMessage: cs.correlationExport.cancelled,
      usedDirectoryPicker,
      usedMultiDownloadFallback,
      downloadUnverified,
    })
    frozenExportRecords = null
    return {
      ok: false,
      code: 'cancelled',
      message: cs.correlationExport.cancelled,
      completedFiles,
      remainingFiles,
    }
  }

  try {
    const retainedForBundle: { alias: string; data: Uint8Array }[] = []

    for (let i = 0; i < records.length; i++) {
      const record = records[i]!
      if (signal.aborted) throw new CorrelationExportCancelledError()

      setCorrelationExportProgress({
        phase: 'exporting',
        fileIndex: i + 1,
        fileTotal,
        currentFileName: record.outputFileName,
        currentMessage: cs.correlationExport.fileProgress(i + 1, fileTotal),
        completedFiles: [...completedFiles],
        remainingFiles: remainingOf(completedFiles),
        usedDirectoryPicker,
        usedMultiDownloadFallback,
        downloadUnverified,
      })

      const written = await exportOneSource(
        record,
        record.outputFileName,
        directory,
        signal,
        (message) => {
          setCorrelationExportProgress({
            phase: 'exporting',
            fileIndex: i + 1,
            fileTotal,
            currentFileName: record.outputFileName,
            currentMessage: message,
            completedFiles: [...completedFiles],
            remainingFiles: remainingOf(completedFiles),
            usedDirectoryPicker,
            usedMultiDownloadFallback,
            downloadUnverified,
          })
        },
        packSupportBundle,
      )
      if (written.delivery === 'download') downloadUnverified = true
      completedFiles.push(written.fileName)
      dataFiles.push(written.fileName)
      if (packSupportBundle && bundleMeta && written.bytes) {
        const alias =
          bundleMeta.aliasByFingerprint.get(fileFingerprint(record.file)) ??
          record.outputFileName
        retainedForBundle.push({ alias, data: written.bytes })
      }
    }

    if (packSupportBundle && bundleMeta && retainedForBundle.length > 0) {
      const zipBytes = buildSupportBundleOutputZip({
        format: bundleMeta.format,
        anonymizedEntries: retainedForBundle,
        omitted: bundleMeta.omitted,
        partial: bundleMeta.partial || Boolean(input.partial) || skippedFiles.length > 0,
      })
      setCorrelationExportProgress({
        phase: 'exporting',
        fileIndex: completedFiles.length + 1,
        fileTotal,
        currentFileName: SUPPORT_BUNDLE_OUTPUT_ZIP_NAME,
        currentMessage: cs.correlationExport.fileProgress(
          completedFiles.length + 1,
          fileTotal,
        ),
        completedFiles: [...completedFiles],
        remainingFiles: remainingOf(completedFiles),
        usedDirectoryPicker,
        usedMultiDownloadFallback,
        downloadUnverified,
      })
      const zipCopy = new Uint8Array(zipBytes.byteLength)
      zipCopy.set(zipBytes)
      const zipBlob = new Blob([zipCopy], { type: 'application/zip' })
      const delivery = await deliverBlob(SUPPORT_BUNDLE_OUTPUT_ZIP_NAME, zipBlob, directory)
      if (delivery === 'download') downloadUnverified = true
      completedFiles.push(SUPPORT_BUNDLE_OUTPUT_ZIP_NAME)
      companionFiles.push(SUPPORT_BUNDLE_OUTPUT_ZIP_NAME)
    }

    let manifestExported = false
    if (manifestNeeded) {
      const snapshot = getSharedMappingClient().getPublishedSnapshot()
      if (snapshot) {
        const manifest = buildShareableCorrelationManifest({
          sources: records,
          snapshot,
          partial: preview.partialOnly || Boolean(input.partial),
        })
        if (manifest) {
          // Apply uniquified names into manifest entries.
          const named = {
            ...manifest,
            sources: manifest.sources.map((s) => {
              const match = records.find((r) => r.sourceId === s.sourceId)
              return match ? { ...s, outputFileName: match.outputFileName } : s
            }),
          }
          const forbiddenSamples = snapshot.entries.map((e) => e.canonical)
          const json = JSON.stringify(named, null, 2)
          try {
            assertShareableManifestHasNoLeaks(json, forbiddenSamples)

            setCorrelationExportProgress({
              phase: 'exporting',
              fileIndex: fileTotal,
              fileTotal,
              currentFileName: SHAREABLE_MANIFEST_FILE_NAME,
              currentMessage: cs.correlationExport.fileProgress(fileTotal, fileTotal),
              completedFiles: [...completedFiles],
              remainingFiles: remainingOf(completedFiles),
              usedDirectoryPicker,
              usedMultiDownloadFallback,
              downloadUnverified,
            })

            if (directory) {
              await writeTextToDirectory(directory, SHAREABLE_MANIFEST_FILE_NAME, json)
            } else {
              const blob = new Blob([json], { type: 'application/json;charset=utf-8' })
              downloadBlob(SHAREABLE_MANIFEST_FILE_NAME, blob)
              downloadUnverified = true
            }
            completedFiles.push(SHAREABLE_MANIFEST_FILE_NAME)
            companionFiles.push(SHAREABLE_MANIFEST_FILE_NAME)
            manifestExported = true
          } catch {
            // Data files already delivered — never fail the whole export on companion safety.
            // Completion stays honest: no AI-shareable badge without a clean manifest.
            setCorrelationExportProgress({
              phase: 'exporting',
              fileIndex: records.length,
              fileTotal,
              currentFileName: '',
              currentMessage: cs.correlationExport.manifestSkippedSafety,
              completedFiles: [...completedFiles],
              remainingFiles: remainingOf(completedFiles),
              usedDirectoryPicker,
              usedMultiDownloadFallback,
              downloadUnverified,
            })
          }
        }
      }
    }

    const exposedIncluded = exportableItems.some((f) => f.security === 'exposed')
    const gapsIncluded = exportableItems.some((f) => f.security === 'gaps')
    const partial = preview.partialOnly || Boolean(input.partial) || skippedFiles.length > 0
    const gateBadge = exposedIncluded || partial
      ? ('NOT_AI_READY' as const)
      : gapsIncluded
        ? ('AI_READY_WITH_GAPS' as const)
        : ('AI_READY' as const)
    const shareableWithAi =
      gateBadge === 'AI_READY' &&
      records.length > 0 &&
      (!manifestNeeded || manifestExported)

    const result = {
      ok: true as const,
      exportedFiles: completedFiles,
      dataFiles,
      companionFiles,
      skippedFiles,
      manifestExported,
      partial,
      exposedIncluded,
      usedDirectoryPicker,
      usedMultiDownloadFallback,
      downloadUnverified,
    }

    markCorrelationExportComplete({
      exportedFiles: completedFiles,
      dataFiles,
      companionFiles,
      skippedFiles: skippedFiles.map((f) => ({
        inputFileName: f.inputFileName,
        outputFileName: f.outputFileName,
        reason: f.skipDetail ?? cs.correlationExport.blockedHint,
      })),
      manifestExported,
      partial,
      exposedIncluded,
      shareableWithAi,
      gateBadge,
      usedDirectoryPicker,
      downloadUnverified,
    })

    return result
  } catch (err) {
    const remainingFiles = remainingOf(completedFiles)
    if (
      err instanceof CorrelationExportCancelledError ||
      err instanceof ExportCancelledError ||
      err instanceof PcapExportCancelledError
    ) {
      setCorrelationExportProgress({
        phase: 'cancelled',
        completedFiles: [...completedFiles],
        remainingFiles,
        currentMessage: cs.correlationExport.cancelledWithDone(completedFiles.length),
        usedDirectoryPicker,
        usedMultiDownloadFallback,
        downloadUnverified,
      })
      return {
        ok: false,
        code: 'cancelled',
        message: cs.correlationExport.cancelledWithDone(completedFiles.length),
        completedFiles,
        remainingFiles,
      }
    }
    setCorrelationExportProgress({
      phase: 'error',
      completedFiles: [...completedFiles],
      remainingFiles,
      currentMessage: err instanceof Error ? err.message : cs.correlationExport.failed,
      usedDirectoryPicker,
      usedMultiDownloadFallback,
      downloadUnverified,
    })
    return {
      ok: false,
      code: 'export-failed',
      message: err instanceof Error ? err.message : cs.correlationExport.failed,
      completedFiles,
      remainingFiles,
    }
  } finally {
    if (activeExportAbort === ac) activeExportAbort = null
    frozenExportRecords = null
  }
}

export function resetCorrelationExportControllerForTests(): void {
  frozenExportRecords = null
}
