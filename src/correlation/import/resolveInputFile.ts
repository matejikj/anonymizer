/**
 * T05 — resolve a dropped File to a ready text/PCAP input (transparent gzip).
 */

import { SourceKind as SK } from '../../domain/sourceArtifact.ts'
import { formatMiB } from '../../domain/capabilityContract.ts'
import { cs } from '../../i18n/cs.ts'
import {
  DecompressError,
  detectCompressedFormat,
  decompressGzipToFile,
  type CompressedFormat,
} from './decompressInput.ts'
import {
  formatInputRejection,
  rejectionForCompressedFormat,
  rejectionForUnsupportedCode,
  type InputRejection,
} from './inputRejection.ts'
import { probeSourceKind, readFileHead, preflightStagingFile } from './sourcePreflightPort.ts'
import type { GzipInflationNote } from './types.ts'

export type { GzipInflationNote }

export type ResolveInputOk = {
  readonly ok: true
  readonly file: File
  readonly kind: typeof SK.Text | typeof SK.Pcap
  readonly gzipInflation?: GzipInflationNote
}

export type ResolveInputFail = {
  readonly ok: false
  readonly rejection: InputRejection
  readonly message: string
}

export type ResolveInputResult = ResolveInputOk | ResolveInputFail

function fail(rejection: InputRejection): ResolveInputFail {
  return { ok: false, rejection, message: formatInputRejection(rejection) }
}

function failCode(code: string): ResolveInputFail {
  return fail(rejectionForUnsupportedCode(code))
}

/**
 * Probe → optional gzip inflate → re-probe → per-kind preflight.
 * Nested compression after inflate is rejected (no automatic recursion).
 */
export async function resolveInputFile(
  file: File,
  options: {
    readonly signal?: AbortSignal
    readonly onInflateProgress?: (inflatedBytes: number) => void
  } = {},
): Promise<ResolveInputResult> {
  let head: Uint8Array
  try {
    head = await readFileHead(file)
  } catch {
    return failCode('read-failed')
  }

  let working = file
  let gzipInflation: GzipInflationNote | undefined
  const firstCompressed = detectCompressedFormat(head)

  if (firstCompressed === 'gzip') {
    try {
      const inflated = await decompressGzipToFile(working, {
        signal: options.signal,
        onProgress: options.onInflateProgress,
      })
      working = inflated.file
      gzipInflation = {
        format: 'gzip',
        compressedBytes: inflated.compressedBytes,
        inflatedBytes: inflated.inflatedBytes,
      }
      try {
        head = await readFileHead(working)
      } catch {
        return failCode('read-failed')
      }
      const nested = detectCompressedFormat(head)
      if (nested !== null) {
        return failCode('nested-compression')
      }
    } catch (err) {
      if (err instanceof DecompressError) {
        return failCode(err.code)
      }
      return failCode('gzip-corrupt')
    }
  } else if (firstCompressed !== null) {
    return fail(rejectionForCompressedFormat(firstCompressed as CompressedFormat))
  }

  const probe = probeSourceKind(head, working.name)
  if (probe.kind === 'compressed') {
    // Should only happen for non-gzip after inflate path; treat as nested/unsupported.
    if (probe.format === 'gzip') return failCode('nested-compression')
    return fail(rejectionForCompressedFormat(probe.format))
  }
  if (probe.kind === 'unsupported') {
    if (probe.code) return failCode(probe.code)
    return failCode('unknown-format')
  }

  const preflight = await preflightStagingFile(working, probe.kind)
  if (!preflight.ok) {
    const mapped = rejectionForUnsupportedCode(preflight.code)
    // Prefer preflight's size-specific message when present, keep structured catalog fields.
    return {
      ok: false,
      rejection: {
        ...mapped,
        reason: preflight.message || mapped.reason,
      },
      message: formatInputRejection({
        ...mapped,
        reason: preflight.message || mapped.reason,
      }),
    }
  }

  return {
    ok: true,
    file: working,
    kind: probe.kind,
    gzipInflation,
  }
}

/** Staging / UI line: „Rozbaleno z .gz (12,3 MiB → 98,1 MiB)“. */
export function formatGzipInflationNote(note: GzipInflationNote): string {
  return cs.inputRejection.gzipInflatedNote
    .replace('{from}', formatMiB(note.compressedBytes))
    .replace('{to}', formatMiB(note.inflatedBytes))
}
