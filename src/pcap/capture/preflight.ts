/**
 * Bounded PCAP/PCAPNG preflight (task-1 Stage 5).
 * Checks file size and magic bytes only — never materializes the whole file.
 */

import {
  BYTES_PER_MIB,
  formatMiB,
  MAX_PCAP_FILE_BYTES,
  withinByteLimit,
} from '../../domain/capabilityContract.ts'
import { CaptureFormat } from '../domain/types'
import { probeFormat } from './probe'

/** Bytes read for magic / container kind detection (not derived from extension). */
export const PCAP_PREFLIGHT_PREFIX_BYTES = 16

export type PcapPreflightFailCode = 'empty' | 'too-large' | 'too-small' | 'unknown-format'

export interface PcapPreflightLimits {
  maxFileBytes: typeof MAX_PCAP_FILE_BYTES
}

export interface PcapPreflightOk {
  ok: true
  byteLength: number
  format: CaptureFormat
  limits: PcapPreflightLimits
}

export interface PcapPreflightFail {
  ok: false
  code: PcapPreflightFailCode
  message: string
  byteLength: number
  limitBytes?: number
}

export type PcapPreflightResult = PcapPreflightOk | PcapPreflightFail

export function pcapPreflightLimits(): PcapPreflightLimits {
  return { maxFileBytes: MAX_PCAP_FILE_BYTES }
}

function tooLargeMessage(byteLength: number): string {
  const over = byteLength - MAX_PCAP_FILE_BYTES
  const sizeLabel =
    over > 0 && over < BYTES_PER_MIB
      ? `${formatMiB(byteLength)} (+${over} B)`
      : formatMiB(byteLength)
  return `Soubor má ${sizeLabel}. Maximum na segment je ${formatMiB(MAX_PCAP_FILE_BYTES)}; větší capture se dělí automaticky v rámci limitu sady.`
}

function tooSmallMessage(): string {
  return 'Soubor je příliš krátký pro rozpoznání formátu PCAP nebo PCAPNG.'
}

function emptyMessage(): string {
  return 'Soubor je prázdný.'
}

function unknownFormatMessage(reason: string): string {
  return `Nepodporovaný formát capture: ${reason}. Rozhoduje obsah souboru (magic bytes), ne přípona.`
}

/**
 * Cheap preflight for a File/Blob — reads at most {@link PCAP_PREFLIGHT_PREFIX_BYTES}.
 */
export async function preflightPcapFile(
  file: Blob,
  options: { signal?: AbortSignal } = {},
): Promise<PcapPreflightResult> {
  const byteLength = file.size

  if (byteLength <= 0) {
    return { ok: false, code: 'empty', message: emptyMessage(), byteLength }
  }

  if (!withinByteLimit(byteLength, MAX_PCAP_FILE_BYTES)) {
    return {
      ok: false,
      code: 'too-large',
      message: tooLargeMessage(byteLength),
      byteLength,
      limitBytes: MAX_PCAP_FILE_BYTES,
    }
  }

  if (byteLength < 4) {
    return {
      ok: false,
      code: 'too-small',
      message: tooSmallMessage(),
      byteLength,
    }
  }

  options.signal?.throwIfAborted()

  const prefixLength = Math.min(PCAP_PREFLIGHT_PREFIX_BYTES, byteLength)
  const prefix = await file.slice(0, prefixLength).arrayBuffer()
  options.signal?.throwIfAborted()

  const probe = probeFormat(prefix)
  if (probe.format === null) {
    return {
      ok: false,
      code: 'unknown-format',
      message: unknownFormatMessage(probe.reason),
      byteLength,
    }
  }

  return {
    ok: true,
    byteLength,
    format: probe.format,
    limits: pcapPreflightLimits(),
  }
}

/** @internal test helper — max MiB label matches contract. */
export const PCAP_PREFLIGHT_MAX_MIB = MAX_PCAP_FILE_BYTES / BYTES_PER_MIB
