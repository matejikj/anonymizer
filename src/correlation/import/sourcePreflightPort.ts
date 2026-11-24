/**
 * Unified content-based source preflight for multi-source import (Stage 27 / T05).
 * Type detection uses magic bytes via source adapters — not file extension or active tab.
 * Compression magic is checked before looksBinary so gzip is not mislabeled as binary.
 */

import { SourceKind as SK } from '../../domain/sourceArtifact'
import { CORRELATION_SESSION_LIMITS, SOURCE_PROBE_HEAD_BYTES, formatMiB } from '../../domain/capabilityContract'
import { probeFormat } from '../../pcap/capture/probe'
import { preflightPcapFile } from '../../pcap/capture/preflight'
import { preflightFile } from '../../features/import-log/preflight'
import { perKindFileLimit, correlationSourceLimits } from '../sourceLimits'
import { detectCompressedFormat } from './decompressInput.ts'
import type { SourceProbeResult } from './types'
import {
  detectTextEncoding,
  looksLikeEvtx,
  looksLikeEtlByName,
  looksLikeSystemdJournal,
} from '../../features/import-log/textEncoding.ts'

const HEAD_BYTES = SOURCE_PROBE_HEAD_BYTES

function looksBinary(head: Uint8Array): boolean {
  // T43 — UTF-16 text has NULs; do not treat as unsupported binary.
  const enc = detectTextEncoding(head)
  if (enc.label === 'utf-16le' || enc.label === 'utf-16be') return false
  const n = Math.min(head.byteLength, HEAD_BYTES)
  for (let i = 0; i < n; i++) {
    if (head[i] === 0) return true
  }
  return false
}

/** True when the head looks like RFC822 / MIME message headers (not a plain log). */
function looksLikeEmailMime(head: Uint8Array): boolean {
  if (head.byteLength === 0) return false
  const text = new TextDecoder('utf-8', { fatal: false }).decode(head.subarray(0, Math.min(head.byteLength, 4096)))
  const lines = text.split(/\r?\n/).slice(0, 40)
  let headerish = 0
  for (const line of lines) {
    if (line.trim() === '') break
    if (/^(from|to|cc|bcc|subject|date|mime-version|content-type|message-id|return-path)\s*:/i.test(line)) {
      headerish += 1
    }
    if (/^mime-version\s*:\s*1\./i.test(line) || /^content-type\s*:\s*multipart\//i.test(line)) {
      return true
    }
  }
  return headerish >= 2
}

function filenameLooksLikeEmail(fileName: string): boolean {
  return /\.(eml|emlx|mime)$/i.test(fileName)
}

export async function readFileHead(file: File, n = HEAD_BYTES): Promise<Uint8Array> {
  const buf = await file.slice(0, n).arrayBuffer()
  return new Uint8Array(buf)
}

/**
 * Content-based kind detection — PCAP magic wins; compression before binary NUL scan;
 * MIME/e-mail is never silently treated as plain text.
 */
export function probeSourceKind(head: Uint8Array, fileName?: string): SourceProbeResult {
  if (head.byteLength >= 4) {
    const buf = head.buffer.slice(head.byteOffset, head.byteOffset + head.byteLength) as ArrayBuffer
    const probed = probeFormat(buf)
    if (probed.format !== null) {
      return { kind: SK.Pcap }
    }
  }

  const compressed = detectCompressedFormat(head)
  if (compressed !== null) {
    return { kind: 'compressed', format: compressed }
  }

  // T43 — binary log formats: reject with export-as-text guidance (not silent binary).
  if (looksLikeEvtx(head)) {
    return { kind: 'unsupported', code: 'evtx' }
  }
  if (looksLikeSystemdJournal(head)) {
    return { kind: 'unsupported', code: 'systemd-journal' }
  }
  if (looksLikeEtlByName(fileName)) {
    return { kind: 'unsupported', code: 'etl' }
  }

  if (looksBinary(head)) {
    return {
      kind: 'unsupported',
      code: 'binary',
    }
  }

  const emailByName = fileName ? filenameLooksLikeEmail(fileName) : false
  const emailByContent = looksLikeEmailMime(head)
  // Content-based MIME probe wins over extension: a .eml whose body is a plain log is text;
  // empty .eml / MIME headers stay unsupported (never silent text).
  if (emailByContent || (emailByName && head.byteLength === 0)) {
    return {
      kind: 'unsupported',
      code: 'mime-unsupported',
    }
  }

  return { kind: SK.Text }
}

export interface StagingPreflightOk {
  readonly ok: true
  readonly kind: typeof SK.Text | typeof SK.Pcap
  readonly byteLength: number
}

export interface StagingPreflightFail {
  readonly ok: false
  readonly code: string
  readonly message: string
}

export type StagingPreflightResult = StagingPreflightOk | StagingPreflightFail

export async function preflightStagingFile(
  file: File,
  kind: typeof SK.Text | typeof SK.Pcap,
): Promise<StagingPreflightResult> {
  const limits = correlationSourceLimits()
  const perFileCap = perKindFileLimit(kind)
  if (file.size > perFileCap) {
    const limitMiB = formatMiB(perFileCap)
    const actualMiB = formatMiB(file.size)
    return {
      ok: false,
      code: 'per-file-limit',
      message: `${file.name}: ${actualMiB} — limit pro tento typ je ${limitMiB}. Ostatní soubory můžete ponechat.`,
    }
  }

  if (kind === SK.Pcap) {
    const result = await preflightPcapFile(file)
    if (!result.ok) {
      return {
        ok: false,
        code: result.code,
        message: result.message,
      }
    }
    return { ok: true, kind: SK.Pcap, byteLength: file.size }
  }

  const result = await preflightFile(file)
  if (!result.ok) {
    return {
      ok: false,
      code: result.code,
      message: result.message,
    }
  }
  void limits
  return { ok: true, kind: SK.Text, byteLength: file.size }
}

export function fileFingerprint(file: File): string {
  return `${file.name}\0${file.size}\0${file.lastModified}`
}

export function aggregateLimitMessage(totalBytes: number): string {
  const limit = CORRELATION_SESSION_LIMITS.maxAggregateBytes
  if (totalBytes <= limit) return ''
  const over = totalBytes - limit
  return `Celkem ${formatMiB(totalBytes)}. Pro tuto relaci je podporováno ${formatMiB(limit)}. Odeberte alespoň ${formatMiB(over)}.`
}

export function stagingAggregateLimitBytes(): number {
  return CORRELATION_SESSION_LIMITS.maxAggregateBytes
}
