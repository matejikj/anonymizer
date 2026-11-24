/**
 * T44 — expand ZIP / TAR / TAR.GZ support bundles into correlation staging sources.
 * Output ZIP builder with REPORT.json (safe aliases only; no mapping/recovery).
 */

import { SourceKind as SK } from '../../domain/sourceArtifact.ts'
import { CORRELATION_SESSION_LIMITS } from '../../domain/capabilityContract.ts'
import { decompressGzipToFile, DecompressError, detectCompressedFormat } from '../import/decompressInput.ts'
import { probeSourceKind } from '../import/sourcePreflightPort.ts'
import { ARCHIVE_LIMITS } from './limits.ts'
import { safeEntryAlias } from './pathSafety.ts'
import { looksLikeZip, readZipArchive, ZipReadError } from './zipReader.ts'
import { looksLikeUstar, readTarArchive, TarReadError } from './tarReader.ts'
import { buildZipStoreArchive } from './zipWriter.ts'
import { classifyForbiddenBundleContent } from './contentGuard.ts'

export type SupportBundleFormat = 'zip' | 'tar' | 'tar-gz'

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
  if (detectCompressedFormat(head) === 'gzip') return 'tar-gz' // confirmed after inflate
  return null
}

interface RawMember {
  readonly relativePath: string
  readonly isDirectory: boolean
  readonly data: Uint8Array
}

async function loadMembers(
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

  if (detectCompressedFormat(head) === 'gzip') {
    try {
      const inflated = await decompressGzipToFile(file, {
        signal,
        maxInflatedBytes: ARCHIVE_LIMITS.maxTotalInflatedBytes,
      })
      const inflatedHead = new Uint8Array(
        await inflated.file.slice(0, 512).arrayBuffer(),
      )
      if (!looksLikeUstar(inflatedHead)) {
        return { code: 'nested-compression' }
      }
      const bytes = new Uint8Array(await inflated.file.arrayBuffer())
      return { format: 'tar-gz', members: readTarArchive(bytes, { signal }) }
    } catch (err) {
      if (err instanceof DecompressError) return { code: err.code }
      if (err instanceof TarReadError) return { code: err.code }
      return { code: 'gzip-corrupt' }
    }
  }

  return { code: 'unknown-format' }
}

/**
 * Expand a support bundle into accepted staging files (≤ correlation source cap)
 * and an omitted list with safe aliases only.
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
  if (formatHint === null && detectCompressedFormat(head) !== 'gzip') {
    return { ok: false, code: 'unknown-format' }
  }

  const loaded = await loadMembers(file, head, options.signal)
  if ('code' in loaded) return { ok: false, code: loaded.code }

  const accepted: SupportBundleAccepted[] = []
  const omitted: SupportBundleOmitted[] = []
  let entryIndex = 0

  for (const member of loaded.members) {
    entryIndex += 1
    const depth = member.relativePath ? member.relativePath.split('/').length : 1

    if (member.isDirectory) {
      omitted.push({
        safeAlias: safeEntryAlias(entryIndex, depth, 'omitted'),
        reason: 'directory',
      })
      continue
    }

    if (member.data.byteLength === 0) {
      omitted.push({
        safeAlias: safeEntryAlias(entryIndex, depth, 'omitted'),
        reason: 'unsupported-type',
      })
      continue
    }

    const forbidden = classifyForbiddenBundleContent(member.data)
    if (forbidden) {
      omitted.push({
        safeAlias: safeEntryAlias(entryIndex, depth, 'omitted'),
        reason: 'forbidden-content',
      })
      continue
    }

    // Nested archive inside ZIP/TAR — do not recurse
    if (looksLikeZip(member.data) || looksLikeUstar(member.data) || detectCompressedFormat(member.data) === 'gzip') {
      // Allow .gz text/pcap? Spec: nested archive without support → omit. Single-file gzip logs
      // inside ZIP are common — treat gzip members as nested-archive omission (caller can
      // re-upload extracted). Safer than silent nested inflate.
      omitted.push({
        safeAlias: safeEntryAlias(entryIndex, depth, 'omitted'),
        reason: 'nested-archive',
      })
      continue
    }

    const probe = probeSourceKind(member.data.subarray(0, Math.min(8192, member.data.byteLength)))
    if (probe.kind === 'unsupported' || probe.kind === 'compressed') {
      omitted.push({
        safeAlias: safeEntryAlias(entryIndex, depth, 'omitted'),
        reason: probe.kind === 'unsupported' && probe.code === 'binary' ? 'binary' : 'unsupported-type',
      })
      continue
    }

    if (accepted.length >= ARCHIVE_LIMITS.maxAcceptedSources) {
      omitted.push({
        safeAlias: safeEntryAlias(entryIndex, depth, probe.kind === SK.Pcap ? 'pcap' : 'text'),
        reason: 'source-limit',
      })
      continue
    }

    const kind = probe.kind
    const alias = safeEntryAlias(entryIndex, depth, kind === SK.Pcap ? 'pcap' : 'text')
    const outFile = new File([member.data.slice()], alias.replace(/\//g, '_'), {
      type: 'application/octet-stream',
    })
    accepted.push({ safeAlias: alias, kind, file: outFile, depth })
  }

  if (accepted.length === 0) {
    return { ok: false, code: 'archive-empty-supported' }
  }

  return {
    ok: true,
    format: loaded.format,
    accepted,
    omitted,
    partial: omitted.some((o) => o.reason === 'source-limit') || accepted.length < loaded.members.filter((m) => !m.isDirectory).length,
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
  return /\.(zip|tar|tgz|tar\.gz)$/i.test(name)
}
