/**
 * T44 / T72 — expand ZIP / TAR / compressed-TAR support bundles into correlation staging sources.
 * Nested archives/compression recurse to ARCHIVE_LIMITS.maxNestDepth with T44 budgets.
 * Output ZIP builder with REPORT.json (safe aliases only; no mapping/recovery).
 */

import { SourceKind as SK } from '../../domain/sourceArtifact.ts'
import { CORRELATION_SESSION_LIMITS } from '../../domain/capabilityContract.ts'
import {
  decompressBytes,
  decompressToFile,
  DecompressError,
  detectCompressedFormat,
  isInflateFormat,
  type InflateFormat,
} from '../import/decompressInput.ts'
import { probeSourceKind } from '../import/sourcePreflightPort.ts'
import { ARCHIVE_LIMITS } from './limits.ts'
import { safeEntryAlias } from './pathSafety.ts'
import { looksLikeZip, readZipArchive, ZipReadError } from './zipReader.ts'
import { looksLikeUstar, readTarArchive, TarReadError } from './tarReader.ts'
import { buildZipStoreArchive } from './zipWriter.ts'
import { classifyForbiddenBundleContent } from './contentGuard.ts'

export type SupportBundleFormat = 'zip' | 'tar' | 'tar-gz' | 'tar-xz' | 'tar-zstd' | 'tar-bzip2'

export type OmittedEntryReason =
  | 'unsupported-type'
  | 'binary'
  | 'directory'
  | 'source-limit'
  | 'forbidden-content'
  | 'path-rejected'
  | 'nested-archive'

export interface SupportBundleAccepted {
  readonly safeAlias: string
  readonly kind: typeof SK.Text | typeof SK.Pcap
  readonly file: File
  readonly depth: number
}

export interface SupportBundleOmitted {
  readonly safeAlias: string
  readonly reason: OmittedEntryReason
}

export interface SupportBundleExpandOk {
  readonly ok: true
  readonly format: SupportBundleFormat
  readonly accepted: readonly SupportBundleAccepted[]
  readonly omitted: readonly SupportBundleOmitted[]
  readonly partial: boolean
}

export interface SupportBundleExpandFail {
  readonly ok: false
  readonly code: string
}

export type SupportBundleExpandResult = SupportBundleExpandOk | SupportBundleExpandFail

export function detectSupportBundleFormat(head: Uint8Array): SupportBundleFormat | null {
  if (looksLikeZip(head)) return 'zip'
  if (looksLikeUstar(head)) return 'tar'
  const compressed = detectCompressedFormat(head)
  if (compressed === 'gzip') return 'tar-gz' // confirmed after inflate
  if (compressed === 'xz') return 'tar-xz'
  if (compressed === 'zstd') return 'tar-zstd'
  if (compressed === 'bzip2') return 'tar-bzip2'
  return null
}

/** Filename heuristic for compressed tar (content still verified after inflate). */
export function looksLikeCompressedTarName(fileName: string): boolean {
  return /\.(tar\.(gz|xz|bz2|zst|zstd)|tgz|txz|tbz2?|tzst)$/i.test(fileName)
}

interface RawMember {
  readonly relativePath: string
  readonly isDirectory: boolean
  readonly data: Uint8Array
}

interface ExpandBudget {
  scanned: number
  inflatedBytes: number
}

async function loadTopLevelMembers(
  file: File,
  head: Uint8Array,
  signal?: AbortSignal,
): Promise<{ format: SupportBundleFormat; members: readonly RawMember[] } | { code: string }> {
  if (looksLikeZip(head)) {
    const bytes = new Uint8Array(await file.arrayBuffer())
    try {
      const members = await readZipArchive(bytes, { signal })
      return { format: 'zip', members }
    } catch (err) {
      if (err instanceof ZipReadError) return { code: err.code }
      return { code: 'zip-truncated' }
    }
  }

  if (looksLikeUstar(head)) {
    const bytes = new Uint8Array(await file.arrayBuffer())
    try {
      return { format: 'tar', members: readTarArchive(bytes, { signal }) }
    } catch (err) {
      if (err instanceof TarReadError) return { code: err.code }
      return { code: 'tar-truncated' }
    }
  }

  const compressed = detectCompressedFormat(head)
  if (compressed !== null && isInflateFormat(compressed)) {
    try {
      const inflated = await decompressToFile(file, compressed, {
        signal,
        maxInflatedBytes: ARCHIVE_LIMITS.maxTotalInflatedBytes,
      })
      const inflatedHead = new Uint8Array(await inflated.file.slice(0, 512).arrayBuffer())
      if (!looksLikeUstar(inflatedHead)) {
        return { code: 'nested-compression' }
      }
      const bytes = new Uint8Array(await inflated.file.arrayBuffer())
      const format: SupportBundleFormat =
        compressed === 'gzip'
          ? 'tar-gz'
          : compressed === 'xz'
            ? 'tar-xz'
            : compressed === 'zstd'
              ? 'tar-zstd'
              : 'tar-bzip2'
      return { format, members: readTarArchive(bytes, { signal }) }
    } catch (err) {
      if (err instanceof DecompressError) return { code: err.code }
      if (err instanceof TarReadError) return { code: err.code }
      return { code: 'gzip-corrupt' }
    }
  }

  return { code: 'unknown-format' }
}

function trackInflated(budget: ExpandBudget, bytes: number): 'ok' | 'archive-bomb' {
  budget.inflatedBytes += bytes
  if (budget.inflatedBytes > ARCHIVE_LIMITS.maxTotalInflatedBytes) return 'archive-bomb'
  if (bytes > ARCHIVE_LIMITS.maxSingleEntryBytes) return 'archive-bomb'
  return 'ok'
}

async function acceptOrOmitMember(
  data: Uint8Array,
  entryIndex: number,
  pathDepth: number,
  nestDepth: number,
  signal: AbortSignal | undefined,
  budget: ExpandBudget,
  accepted: SupportBundleAccepted[],
  omitted: SupportBundleOmitted[],
): Promise<'ok' | 'fail'> {
  if (budget.scanned >= ARCHIVE_LIMITS.maxEntriesScanned) {
    omitted.push({
      safeAlias: safeEntryAlias(entryIndex, pathDepth, 'omitted'),
      reason: 'source-limit',
    })
    return 'ok'
  }
  budget.scanned += 1

  if (data.byteLength === 0) {
    omitted.push({
      safeAlias: safeEntryAlias(entryIndex, pathDepth, 'omitted'),
      reason: 'unsupported-type',
    })
    return 'ok'
  }

  if (trackInflated(budget, data.byteLength) !== 'ok') {
    return 'fail'
  }

  const forbidden = classifyForbiddenBundleContent(data)
  if (forbidden) {
    omitted.push({
      safeAlias: safeEntryAlias(entryIndex, pathDepth, 'omitted'),
      reason: 'forbidden-content',
    })
    return 'ok'
  }

  const container =
    looksLikeZip(data)
    || looksLikeUstar(data)
    || detectCompressedFormat(data) !== null

  if (container) {
    if (nestDepth >= ARCHIVE_LIMITS.maxNestDepth) {
      omitted.push({
        safeAlias: safeEntryAlias(entryIndex, pathDepth, 'omitted'),
        reason: 'nested-archive',
      })
      return 'ok'
    }
    const nested = await expandNestedBytes(data, nestDepth + 1, signal, budget, accepted, omitted, entryIndex)
    if (nested === 'fail') return 'fail'
    return 'ok'
  }

  const probe = probeSourceKind(data.subarray(0, Math.min(8192, data.byteLength)))
  if (probe.kind === 'unsupported' || probe.kind === 'compressed') {
    omitted.push({
      safeAlias: safeEntryAlias(entryIndex, pathDepth, 'omitted'),
      reason: probe.kind === 'unsupported' && probe.code === 'binary' ? 'binary' : 'unsupported-type',
    })
    return 'ok'
  }

  if (accepted.length >= ARCHIVE_LIMITS.maxAcceptedSources) {
    omitted.push({
      safeAlias: safeEntryAlias(entryIndex, pathDepth, probe.kind === SK.Pcap ? 'pcap' : 'text'),
      reason: 'source-limit',
    })
    return 'ok'
  }

  const kind = probe.kind
  const alias = safeEntryAlias(entryIndex, pathDepth, kind === SK.Pcap ? 'pcap' : 'text')
  const outFile = new File([data.slice()], alias.replace(/\//g, '_'), {
    type: 'application/octet-stream',
  })
  accepted.push({ safeAlias: alias, kind, file: outFile, depth: pathDepth })
  return 'ok'
}

async function expandNestedBytes(
  data: Uint8Array,
  nestDepth: number,
  signal: AbortSignal | undefined,
  budget: ExpandBudget,
  accepted: SupportBundleAccepted[],
  omitted: SupportBundleOmitted[],
  parentIndex: number,
): Promise<'ok' | 'fail'> {
  // ZIP
  if (looksLikeZip(data)) {
    try {
      const members = await readZipArchive(data, { signal })
      return walkMembers(members, nestDepth, signal, budget, accepted, omitted, parentIndex)
    } catch (err) {
      if (err instanceof ZipReadError) {
        omitted.push({
          safeAlias: safeEntryAlias(parentIndex, nestDepth, 'omitted'),
          reason: 'nested-archive',
        })
        return 'ok'
      }
      return 'fail'
    }
  }

  // TAR
  if (looksLikeUstar(data)) {
    try {
      const members = readTarArchive(data, { signal })
      return walkMembers(members, nestDepth, signal, budget, accepted, omitted, parentIndex)
    } catch {
      omitted.push({
        safeAlias: safeEntryAlias(parentIndex, nestDepth, 'omitted'),
        reason: 'nested-archive',
      })
      return 'ok'
    }
  }

  const compressed = detectCompressedFormat(data)
  if (compressed !== null && isInflateFormat(compressed)) {
    try {
      const inflated = await decompressBytes(data, compressed as InflateFormat, {
        signal,
        maxInflatedBytes: ARCHIVE_LIMITS.maxSingleEntryBytes,
        nameHint: `nested.${compressed}`,
      })
      if (trackInflated(budget, inflated.inflatedBytes) !== 'ok') return 'fail'
      // Recurse into inflated payload (may be tar/zip/source/another compress layer).
      return acceptOrOmitMember(
        inflated.data,
        parentIndex,
        nestDepth,
        nestDepth,
        signal,
        budget,
        accepted,
        omitted,
      )
    } catch (err) {
      if (err instanceof DecompressError) {
        omitted.push({
          safeAlias: safeEntryAlias(parentIndex, nestDepth, 'omitted'),
          reason: 'nested-archive',
        })
        return 'ok'
      }
      return 'fail'
    }
  }

  omitted.push({
    safeAlias: safeEntryAlias(parentIndex, nestDepth, 'omitted'),
    reason: 'nested-archive',
  })
  return 'ok'
}

async function walkMembers(
  members: readonly RawMember[],
  nestDepth: number,
  signal: AbortSignal | undefined,
  budget: ExpandBudget,
  accepted: SupportBundleAccepted[],
  omitted: SupportBundleOmitted[],
  indexBase: number,
): Promise<'ok' | 'fail'> {
  let local = 0
  for (const member of members) {
    local += 1
    const entryIndex = indexBase * 1000 + local
    const pathDepth = member.relativePath ? member.relativePath.split('/').length : 1

    if (member.isDirectory) {
      omitted.push({
        safeAlias: safeEntryAlias(entryIndex, pathDepth, 'omitted'),
        reason: 'directory',
      })
      continue
    }

    const status = await acceptOrOmitMember(
      member.data,
      entryIndex,
      pathDepth,
      nestDepth,
      signal,
      budget,
      accepted,
      omitted,
    )
    if (status === 'fail') return 'fail'
  }
  return 'ok'
}

/**
 * Expand a support bundle into accepted staging files and an omitted list with safe aliases only.
 * T72: recurse nested archives/compression to maxNestDepth; accept all supported members
 * within aggregate size (no hard reject at 8 sources).
 */
export async function expandSupportBundle(
  file: File,
  options: { readonly signal?: AbortSignal } = {},
): Promise<SupportBundleExpandResult> {
  let head: Uint8Array
  try {
    head = new Uint8Array(await file.slice(0, 512).arrayBuffer())
  } catch {
    return { ok: false, code: 'read-failed' }
  }

  const formatHint = detectSupportBundleFormat(head)
  if (formatHint === null) {
    return { ok: false, code: 'unknown-format' }
  }

  // Compressed top-level that is not actually a tar → caller should use resolveInputFile.
  if (
    formatHint === 'tar-gz'
    || formatHint === 'tar-xz'
    || formatHint === 'tar-zstd'
    || formatHint === 'tar-bzip2'
  ) {
    // loadTopLevelMembers returns nested-compression when inflate is not ustar
  }

  const loaded = await loadTopLevelMembers(file, head, options.signal)
  if ('code' in loaded) return { ok: false, code: loaded.code }

  const accepted: SupportBundleAccepted[] = []
  const omitted: SupportBundleOmitted[] = []
  const budget: ExpandBudget = { scanned: 0, inflatedBytes: 0 }

  const walked = await walkMembers(
    loaded.members,
    1,
    options.signal,
    budget,
    accepted,
    omitted,
    1,
  )
  if (walked === 'fail') {
    return { ok: false, code: 'archive-bomb' }
  }

  if (accepted.length === 0) {
    return { ok: false, code: 'archive-empty-supported' }
  }

  return {
    ok: true,
    format: loaded.format,
    accepted,
    omitted,
    partial:
      omitted.some((o) => o.reason === 'source-limit' || o.reason === 'nested-archive')
      || accepted.length < loaded.members.filter((m) => !m.isDirectory).length,
  }
}

export interface SupportBundleReport {
  readonly schema: 'rnd-log-anonymizer-support-bundle-report'
  readonly schemaVersion: 1
  readonly format: SupportBundleFormat
  readonly accepted: readonly { readonly alias: string; readonly kind: string }[]
  readonly omitted: readonly { readonly alias: string; readonly reason: OmittedEntryReason }[]
  readonly partial: boolean
  readonly maxSources: number
}

export function buildSupportBundleReport(
  format: SupportBundleFormat,
  accepted: readonly SupportBundleAccepted[],
  omitted: readonly SupportBundleOmitted[],
  partial: boolean,
): SupportBundleReport {
  return {
    schema: 'rnd-log-anonymizer-support-bundle-report',
    schemaVersion: 1,
    format,
    accepted: accepted.map((a) => ({ alias: a.safeAlias, kind: a.kind })),
    omitted: omitted.map((o) => ({ alias: o.safeAlias, reason: o.reason })),
    partial,
    maxSources: CORRELATION_SESSION_LIMITS.maxSources,
  }
}

/**
 * Build shareable output ZIP from already-anonymized entry bytes + report.
 * Never include mapping bundle or recovery.
 */
export function buildSupportBundleOutputZip(options: {
  readonly format: SupportBundleFormat
  readonly anonymizedEntries: readonly { readonly alias: string; readonly data: Uint8Array }[]
  readonly omitted: readonly SupportBundleOmitted[]
  readonly partial: boolean
}): Uint8Array {
  const report = buildSupportBundleReport(
    options.format,
    options.anonymizedEntries.map((e) => ({
      safeAlias: e.alias,
      kind: e.alias.endsWith('.pcap') ? SK.Pcap : SK.Text,
      file: new File([], e.alias),
      depth: e.alias.split('/').length,
    })),
    options.omitted,
    options.partial,
  )
  const reportBytes = new TextEncoder().encode(`${JSON.stringify(report, null, 2)}\n`)
  const zipEntries = [
    ...options.anonymizedEntries.map((e) => ({ path: e.alias, data: e.data })),
    { path: 'REPORT.json', data: reportBytes },
  ]
  return buildZipStoreArchive(zipEntries)
}

export function isSupportBundleFileName(name: string): boolean {
  return /\.(zip|tar|tgz|tar\.gz|tar\.xz|txz|tar\.bz2|tbz2?|tar\.zst|tar\.zstd|tzst)$/i.test(name)
}
