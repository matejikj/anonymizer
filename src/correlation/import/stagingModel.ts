/**
 * Module-scoped multi-source staging list (Stage 27 / T05 / T44 archives).
 */

import { SourceKind as SK } from '../../domain/sourceArtifact'
import { formatMiB } from '../../domain/capabilityContract'
import { getActiveProfile } from '../../features/rules/activeProfile'
import { getActivePcapProfile } from '../../pcap/profile/activePcapProfile'
import { defaultOutputFileName } from '../sourceLimits'
import { fileFingerprint, readFileHead, stagingAggregateLimitBytes } from './sourcePreflightPort'
import { resolveInputFile } from './resolveInputFile.ts'
import { detectCompressedFormat } from './decompressInput.ts'
import { formatInputRejection, rejectionForUnsupportedCode } from './inputRejection.ts'
import {
  expandSupportBundle,
  looksLikeCompressedTarName,
  type SupportBundleExpandOk,
  type SupportBundleFormat,
  type SupportBundleOmitted,
} from '../archive/supportBundle.ts'
import { looksLikeZip } from '../archive/zipReader.ts'
import { looksLikeUstar } from '../archive/tarReader.ts'
import { isInflateFormat } from './decompressInput.ts'
import type { GzipInflationNote, StagingBatchSummary, StagingItem, StagingItemReady } from './types'

export interface LastSupportBundleMeta {
  readonly format: SupportBundleFormat
  readonly omitted: readonly SupportBundleOmitted[]
  readonly partial: boolean
  /** fileFingerprint → safe alias path (hierarchy preserved; no original names). */
  readonly aliasByFingerprint: ReadonlyMap<string, string>
}

let stagingItems: StagingItem[] = []
let stagingRevision = 0
/** T44 — last expanded support bundle (safe aliases only) for outcome + output ZIP. */
let lastBundleMeta: LastSupportBundleMeta | null = null

export function getLastSupportBundleOmissions(): readonly SupportBundleOmitted[] {
  return lastBundleMeta?.omitted ?? []
}

export function getLastSupportBundleMeta(): LastSupportBundleMeta | null {
  return lastBundleMeta
}

export function getStagingRevision(): number {
  return stagingRevision
}

export function getStagingItems(): readonly StagingItem[] {
  return stagingItems
}

export function clearStagingItems(): void {
  stagingItems = []
  lastBundleMeta = null
  stagingRevision += 1
}

function isArchiveCandidate(file: File, head: Uint8Array): boolean {
  if (looksLikeZip(head) || looksLikeUstar(head)) return true
  const compressed = detectCompressedFormat(head)
  // T72 — compressed tar (.tar.gz / .tar.xz / …); single-file .log.xz goes through resolveInputFile.
  if (compressed !== null && isInflateFormat(compressed) && looksLikeCompressedTarName(file.name)) {
    return true
  }
  return false
}

export function replaceStagingItems(items: readonly StagingItem[]): void {
  stagingItems = [...items]
  stagingRevision += 1
}

export function removeStagingItem(id: string): StagingItem | null {
  const idx = stagingItems.findIndex((i) => i.id === id)
  if (idx < 0) return null
  const [removed] = stagingItems.splice(idx, 1)
  stagingRevision += 1
  return removed ?? null
}

function profileLabelForKind(kind: typeof SK.Text | typeof SK.Pcap): string {
  return kind === SK.Pcap ? getActivePcapProfile().name : getActiveProfile().profile.name
}

function newItemId(file: File, index: number, used: Set<string>): string {
  const base =
    file.name
      .replace(/\.[^.]+$/, '')
      .replace(/[^a-zA-Z0-9._-]+/g, '-')
      .slice(0, 40) || 'source'
  let id = `${base}-${index}`
  let n = 0
  while (used.has(id)) {
    n += 1
    id = `${base}-${index}-${n}`
  }
  used.add(id)
  return id
}

function readyItem(
  id: string,
  file: File,
  kind: typeof SK.Text | typeof SK.Pcap,
  opts?: {
    readonly gzipInflation?: GzipInflationNote
    readonly sourceFileName?: string
  },
): StagingItemReady {
  return {
    id,
    file,
    fileName: opts?.sourceFileName ?? file.name,
    byteLength: file.size,
    status: 'ready',
    kind,
    profileLabel: profileLabelForKind(kind),
    gzipInflation: opts?.gzipInflation,
    sourceFileName: opts?.sourceFileName,
  }
}

export async function buildStagingItemsFromFiles(
  files: readonly File[],
  existingFingerprints: ReadonlyMap<string, StagingItemReady> = new Map(),
  options: { readonly signal?: AbortSignal } = {},
): Promise<StagingItem[]> {
  const usedIds = new Set<string>()
  const fingerprintToReady = new Map(existingFingerprints)
  const out: StagingItem[] = []

  for (let index = 0; index < files.length; index++) {
    const file = files[index]!
    const id = newItemId(file, index, usedIds)
    const fp = fileFingerprint(file)

    const prior = fingerprintToReady.get(fp)
    if (prior) {
      const dup = readyItem(id, file, prior.kind, {
        gzipInflation: prior.gzipInflation,
        sourceFileName: prior.sourceFileName ?? prior.fileName,
      })
      out.push({
        ...dup,
        status: 'duplicate-warning',
        duplicateOfId: prior.id,
        duplicateOfName: prior.fileName,
      })
      continue
    }

    // T44 — ZIP / TAR / TAR.GZ → multiple safe-aliased sources
    let head: Uint8Array | null = null
    try {
      head = await readFileHead(file)
    } catch {
      head = null
    }
    if (head && isArchiveCandidate(file, head)) {
      const expanded = await expandSupportBundle(file, { signal: options.signal })
      if (expanded.ok) {
        const aliasByFingerprint = new Map<string, string>()
        for (const entry of expanded.accepted) {
          aliasByFingerprint.set(fileFingerprint(entry.file), entry.safeAlias)
        }
        lastBundleMeta = {
          format: expanded.format,
          omitted: expanded.omitted,
          partial: expanded.partial,
          aliasByFingerprint,
        }
        appendExpandedBundle(out, expanded, file, usedIds, fingerprintToReady, index)
        continue
      }
      // Compressed named like tar.* but payload is a single log/PCAP — fall through to resolve.
      if (expanded.code !== 'nested-compression') {
        const rejection = rejectionForUnsupportedCode(expanded.code)
        out.push({
          id,
          file,
          fileName: file.name,
          byteLength: file.size,
          status: 'error',
          code: expanded.code,
          message: formatInputRejection(rejection),
          rejection,
          recoveryAction: 'remove',
        })
        continue
      }
    }

    const resolved = await resolveInputFile(file, { signal: options.signal })
    if (!resolved.ok) {
      out.push({
        id,
        file,
        fileName: file.name,
        byteLength: file.size,
        status: 'error',
        code: resolved.rejection.code,
        message: resolved.message,
        rejection: resolved.rejection,
        recoveryAction: 'remove',
      })
      continue
    }

    const item = readyItem(id, resolved.file, resolved.kind, {
      gzipInflation: resolved.gzipInflation,
      sourceFileName: resolved.gzipInflation ? file.name : undefined,
    })
    fingerprintToReady.set(fp, item)
    out.push(item)
  }

  return out
}

function appendExpandedBundle(
  out: StagingItem[],
  expanded: SupportBundleExpandOk,
  archiveFile: File,
  usedIds: Set<string>,
  fingerprintToReady: Map<string, StagingItemReady>,
  baseIndex: number,
): void {
  for (let i = 0; i < expanded.accepted.length; i++) {
    const entry = expanded.accepted[i]!
    const id = newItemId(entry.file, baseIndex * 100 + i, usedIds)
    const fp = fileFingerprint(entry.file)
    const prior = fingerprintToReady.get(fp)
    if (prior) {
      out.push({
        ...readyItem(id, entry.file, entry.kind, {
          sourceFileName: archiveFile.name,
        }),
        status: 'duplicate-warning',
        duplicateOfId: prior.id,
        duplicateOfName: prior.fileName,
      })
      continue
    }
    // Display name = safe alias (never original member path)
    const item: StagingItemReady = {
      id,
      file: entry.file,
      fileName: entry.safeAlias,
      byteLength: entry.file.size,
      status: 'ready',
      kind: entry.kind,
      profileLabel: profileLabelForKind(entry.kind),
      sourceFileName: archiveFile.name,
    }
    fingerprintToReady.set(fp, item)
    out.push(item)
  }
}

export async function mergeFilesIntoStaging(files: readonly File[]): Promise<void> {
  if (files.length === 0) return
  const existingReady = new Map<string, StagingItemReady>()
  for (const item of stagingItems) {
    if (item.status === 'ready' || item.status === 'duplicate-warning') {
      existingReady.set(fileFingerprint(item.file), {
        id: item.id,
        file: item.file,
        fileName: item.fileName,
        byteLength: item.byteLength,
        status: 'ready',
        kind: item.kind,
        profileLabel: item.profileLabel,
        gzipInflation: item.gzipInflation,
        sourceFileName: item.sourceFileName,
      })
    }
  }
  const startIndex = stagingItems.length
  const usedIds = new Set(stagingItems.map((i) => i.id))
  const newItems = await buildStagingItemsFromFiles(files, existingReady)
  for (const item of newItems) {
    if (usedIds.has(item.id)) {
      let n = 0
      let nextId = `${item.id}-add`
      while (usedIds.has(nextId)) {
        n += 1
        nextId = `${item.id}-add-${n}`
      }
      Object.assign(item, { id: nextId })
      usedIds.add(nextId)
    } else {
      usedIds.add(item.id)
    }
    void startIndex
  }
  stagingItems = [...stagingItems, ...newItems]
  stagingRevision += 1
}

export function getReadyStagingItems(): readonly StagingItemReady[] {
  return stagingItems.filter(
    (i): i is StagingItemReady => i.status === 'ready' || i.status === 'duplicate-warning',
  )
}

export function buildStagingSummary(items: readonly StagingItem[] = stagingItems): StagingBatchSummary {
  const limit = stagingAggregateLimitBytes()
  let totalBytes = 0
  let readyCount = 0
  let errorCount = 0
  let duplicateCount = 0
  const readySizes: { id: string; bytes: number }[] = []

  for (const item of items) {
    if (item.status === 'error') {
      errorCount += 1
      continue
    }
    if (item.status === 'duplicate-warning') duplicateCount += 1
    readyCount += 1
    totalBytes += item.byteLength
    readySizes.push({ id: item.id, bytes: item.byteLength })
  }

  readySizes.sort((a, b) => b.bytes - a.bytes)
  const aggregateOverLimit = totalBytes > limit
  const bytesToRemove = aggregateOverLimit ? totalBytes - limit : null

  return {
    fileCount: items.length,
    totalBytes,
    readyCount,
    errorCount,
    duplicateCount,
    aggregateLimitBytes: limit,
    aggregateOverLimit,
    bytesToRemove,
    largestReadyIds: readySizes.slice(0, 3).map((r) => r.id),
  }
}

export function formatStagingSize(bytes: number): string {
  return formatMiB(bytes)
}

export function stagingDescriptorOutputName(item: StagingItemReady): string {
  // Support-bundle entries: display fileName is the safe alias (may contain '/').
  const base =
    item.sourceFileName && item.fileName.includes('/')
      ? item.fileName.replace(/\//g, '_')
      : item.file.name
  return defaultOutputFileName(item.kind, base)
}

export function resetStagingForTests(): void {
  stagingItems = []
  lastBundleMeta = null
  stagingRevision = 0
}
