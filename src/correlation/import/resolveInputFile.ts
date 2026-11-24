/**
 * T05 / T72 — resolve a dropped File to a ready text/PCAP input (transparent inflate).
 */

import { SourceKind as SK } from '../../domain/sourceArtifact.ts'
import { formatMiB } from '../../domain/capabilityContract.ts'
import { cs } from '../../i18n/cs.ts'
import {
  DecompressError,
  detectCompressedFormat,
  decompressToFile,
  isInflateFormat,
  MAX_COMPRESSION_NEST_DEPTH,
  type CompressedFormat,
  type InflateFormat,
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
 * Probe → optional multi-layer inflate (depth ≤ 4) → re-probe → per-kind preflight.
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
  let inflation: GzipInflationNote | undefined
  let nestDepth = 0

  for (;;) {
    const compressed = detectCompressedFormat(head)
    if (compressed === null) break
    if (compressed === 'zip') {
      // ZIP containers are expanded via support-bundle path, not here.
      return fail(rejectionForCompressedFormat(compressed as CompressedFormat))
    }
    if (!isInflateFormat(compressed)) {
      return fail(rejectionForCompressedFormat(compressed))
    }
    if (nestDepth >= MAX_COMPRESSION_NEST_DEPTH) {
      return failCode('nested-compression')
    }
    try {
      const inflated = await decompressToFile(working, compressed, {
        signal: options.signal,
        onProgress: options.onInflateProgress,
      })
      working = inflated.file
      inflation = {
        format: inflated.format,
        compressedBytes: inflated.compressedBytes,
        inflatedBytes: inflated.inflatedBytes,
      }
      nestDepth += 1
      try {
        head = await readFileHead(working)
      } catch {
        return failCode('read-failed')
      }
    } catch (err) {
      if (err instanceof DecompressError) {
        return failCode(err.code)
      }
      return failCode('gzip-corrupt')
    }
  }

  const probe = probeSourceKind(head, working.name)
  if (probe.kind === 'compressed') {
    if (isInflateFormat(probe.format) && nestDepth >= MAX_COMPRESSION_NEST_DEPTH) {
      return failCode('nested-compression')
    }
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
    gzipInflation: inflation,
  }
}

/** Staging / UI line: „Rozbaleno z .gz (12,3 MiB → 98,1 MiB)“. */
export function formatGzipInflationNote(note: GzipInflationNote): string {
  const format =
    note.format === 'gzip'
      ? '.gz'
      : note.format === 'xz'
        ? '.xz'
        : note.format === 'zstd'
          ? '.zst'
          : '.bz2'
  return cs.inputRejection.gzipInflatedNote
    .replace('{format}', format)
    .replace('{from}', formatMiB(note.compressedBytes))
    .replace('{to}', formatMiB(note.inflatedBytes))
}

export function formatInflationNote(note: GzipInflationNote): string {
  return formatGzipInflationNote(note)
}

/** Exported for callers that need the inflate format label. */
export type { InflateFormat }
