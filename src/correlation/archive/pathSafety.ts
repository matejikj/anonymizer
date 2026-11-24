/**
 * T44 — archive path validation and safe output aliases (never echo original names).
 */

import { ARCHIVE_LIMITS } from './limits.ts'

export type PathRejectReason =
  | 'empty'
  | 'absolute'
  | 'traversal'
  | 'nul'
  | 'too-long'
  | 'unsafe-char'
  | 'reserved'

export interface ValidatedArchivePath {
  readonly ok: true
  /** Normalized relative POSIX path without leading ./ */
  readonly relative: string
  readonly segments: readonly string[]
  readonly isDirectory: boolean
}

export interface RejectedArchivePath {
  readonly ok: false
  readonly reason: PathRejectReason
}

export type ArchivePathResult = ValidatedArchivePath | RejectedArchivePath

/** Validate a ZIP/TAR member name. Does not reveal the original string to callers beyond ok/reason. */
export function validateArchivePath(raw: string): ArchivePathResult {
  if (!raw || raw.length === 0) return { ok: false, reason: 'empty' }
  if (raw.length > ARCHIVE_LIMITS.maxPathBytes) return { ok: false, reason: 'too-long' }
  if (raw.includes('\0')) return { ok: false, reason: 'nul' }

  let path = raw.replace(/\\/g, '/')
  const isDirectory = path.endsWith('/')
  if (isDirectory) path = path.slice(0, -1)
  if (path.startsWith('/') || /^[A-Za-z]:/.test(path) || path.startsWith('//')) {
    return { ok: false, reason: 'absolute' }
  }
  if (path.startsWith('./')) path = path.slice(2)

  const segments = path.split('/').filter((s) => s.length > 0)
  if (segments.length === 0) {
    return isDirectory ? { ok: true, relative: '', segments: [], isDirectory: true } : { ok: false, reason: 'empty' }
  }
  for (const seg of segments) {
    if (seg === '.' || seg === '..') return { ok: false, reason: 'traversal' }
    if (seg === '~') return { ok: false, reason: 'reserved' }
    // Control chars / path tricks
    if (/[\x00-\x1f\x7f]/.test(seg)) return { ok: false, reason: 'unsafe-char' }
  }
  return {
    ok: true,
    relative: segments.join('/'),
    segments,
    isDirectory,
  }
}

/**
 * Build a shareable path alias that preserves hierarchy depth but not original labels.
 * Extension reflects probed kind only.
 */
export function safeEntryAlias(
  entryIndex: number,
  depth: number,
  kind: 'text' | 'pcap' | 'omitted',
): string {
  const dirs: string[] = []
  for (let i = 0; i < Math.max(0, depth - 1); i++) {
    dirs.push(`d${i}`)
  }
  const ext = kind === 'pcap' ? '.pcap' : kind === 'text' ? '.log' : '.bin'
  const base = `e${String(entryIndex).padStart(2, '0')}${ext}`
  return [...dirs, base].join('/')
}
