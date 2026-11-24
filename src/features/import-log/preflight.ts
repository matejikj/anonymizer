/**
 * Streamed capacity preflight (ARCHITECTURE §3.1 / §8 / T43).
 * Runs before releasing the previous session / building editors.
 */

import { cs } from '../../i18n/cs.ts'
import { INPUT_LIMITS, BYTES_PER_MIB } from './inputLimits.ts'
import { utf8ByteLength } from './streamingDecode.ts'
import {
  createTextDecoder,
  detectTextEncoding,
  looksLikeEvtx,
  looksLikeEtlByName,
  looksLikeSystemdJournal,
  type TextEncodingLabel,
  type EncodingConfidence,
} from './textEncoding.ts'

export type LogMode = 'common' | 'large'

export interface PreflightOk {
  ok: true
  mode: LogMode
  byteLength: number
  lineCount: number
  /** True when decoder substituted � for invalid sequences. */
  hadInvalidUtf8: boolean
  /** T43 — detected or override encoding used for decode. */
  sourceEncoding: TextEncodingLabel
  encodingConfidence: EncodingConfidence
  encodingCandidates: readonly TextEncodingLabel[]
}

export interface PreflightFail {
  ok: false
  code:
    | 'too-large-file'
    | 'too-large-paste'
    | 'too-many-lines'
    | 'empty'
    | 'binary'
    | 'evtx'
    | 'systemd-journal'
    | 'etl'
  message: string
}

function rejectionMessage(
  block: { title: string; reason: string; action: string },
): string {
  return `${block.title} ${block.reason} ${block.action}`
}

export type PreflightResult = PreflightOk | PreflightFail

export function classifyMode(byteLength: number, lineCount: number): LogMode {
  if (
    byteLength > INPUT_LIMITS.commonMaxBytes ||
    lineCount > INPUT_LIMITS.commonMaxLines
  ) {
    return 'large'
  }
  return 'common'
}

function looksLikeRecoveryMagic(sample: Uint8Array): boolean {
  return (
    sample.byteLength >= 8
    && sample[0] === 0x52
    && sample[1] === 0x4e
    && sample[2] === 0x44
    && sample[3] === 0x50
    && sample[4] === 0x43
    && sample[5] === 0x41
    && sample[6] === 0x50
    && sample[7] === 0x52
  )
}

function looksBinary(sample: Uint8Array, encoding: TextEncodingLabel): boolean {
  if (looksLikeRecoveryMagic(sample)) return true
  // UTF-16 naturally contains NUL code units — not binary for T43.
  if (encoding === 'utf-16le' || encoding === 'utf-16be') return false
  const n = Math.min(sample.byteLength, 8192)
  for (let i = 0; i < n; i++) {
    if (sample[i] === 0) return true
  }
  return false
}

/** Count physical lines from a complete string (LF / CRLF / CR). */
export function countPhysicalLinesQuick(text: string): number {
  if (text.length === 0) return 0
  let lines = 1
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (c === 10) lines++
    else if (c === 13) {
      lines++
      if (text.charCodeAt(i + 1) === 10) i++
    }
  }
  return lines
}

/**
 * Incremental newline counter for streamed decode chunks.
 * `pendingCr` is true when the previous chunk ended with CR (possible CRLF split).
 */
export function countNewlinesIncremental(
  text: string,
  pendingCr: boolean,
): { completeLines: number; pendingCr: boolean } {
  let complete = 0
  let cr = pendingCr
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (cr) {
      cr = false
      if (c === 10) {
        complete++
        continue
      }
      complete++
    }
    if (c === 13) cr = true
    else if (c === 10) complete++
  }
  return { completeLines: complete, pendingCr: cr }
}

export interface PreflightFileOptions {
  readonly signal?: AbortSignal
  /** T43 — force encoding (skip auto-detect). */
  readonly encoding?: TextEncodingLabel
}

/**
 * Cheap streamed preflight for a File/Blob — does not build editors.
 */
export async function preflightFile(
  file: Blob,
  options: PreflightFileOptions = {},
): Promise<PreflightResult> {
  if (file.size <= 0) {
    return { ok: false, code: 'empty', message: 'Soubor je prázdný.' }
  }
  if (file.size > INPUT_LIMITS.fileMaxBytes) {
    return {
      ok: false,
      code: 'too-large-file',
      message: `Soubor má ${(file.size / BYTES_PER_MIB).toFixed(1)} MiB. Maximum je ${INPUT_LIMITS.fileMaxBytes / BYTES_PER_MIB} MiB. Rozdělte log na menší části.`,
    }
  }

  const head = new Uint8Array(await file.slice(0, 8192).arrayBuffer())
  if (looksLikeEvtx(head)) {
    return { ok: false, code: 'evtx', message: rejectionMessage(cs.inputRejection.evtx) }
  }
  if (looksLikeSystemdJournal(head)) {
    return {
      ok: false,
      code: 'systemd-journal',
      message: rejectionMessage(cs.inputRejection.systemdJournal),
    }
  }
  const fileName = typeof File !== 'undefined' && file instanceof File ? file.name : undefined
  if (looksLikeEtlByName(fileName)) {
    return { ok: false, code: 'etl', message: rejectionMessage(cs.inputRejection.etl) }
  }

  const detected = detectTextEncoding(head)
  const encoding = options.encoding ?? detected.label
  const confidence = options.encoding
    ? detected.bomLength > 0 && detected.label === options.encoding
      ? ('bom' as const)
      : ('high' as const)
    : detected.confidence
  const candidates = detected.candidates

  const decoder = createTextDecoder(encoding, { fatal: false })
  let completeLines = 0
  let pendingCr = false
  let hadInvalidUtf8 = false
  let checkedBinary = false
  let sawContent = false

  const ingest = (piece: string, final: boolean) => {
    if (piece.includes('\uFFFD')) hadInvalidUtf8 = true
    if (piece.length > 0) sawContent = true
    const r = countNewlinesIncremental(piece, pendingCr)
    completeLines += r.completeLines
    pendingCr = r.pendingCr
    if (final) {
      if (pendingCr) {
        completeLines++
        pendingCr = false
      }
      const lineCount = sawContent ? completeLines + 1 : 0
      return lineCount
    }
    return completeLines + (sawContent ? 1 : 0)
  }

  const okResult = (lineCount: number): PreflightOk => ({
    ok: true,
    mode: classifyMode(file.size, lineCount),
    byteLength: file.size,
    lineCount,
    hadInvalidUtf8,
    sourceEncoding: encoding,
    encodingConfidence: confidence,
    encodingCandidates: candidates,
  })

  if (typeof file.stream === 'function') {
    const reader = file.stream().getReader()
    for (;;) {
      if (options.signal?.aborted) throw new DOMException('Aborted', 'AbortError')
      const { done, value } = await reader.read()
      if (done) break
      if (!value || value.byteLength === 0) continue
      if (!checkedBinary) {
        checkedBinary = true
        if (looksBinary(value, encoding)) {
          return {
            ok: false,
            code: 'binary',
            message: 'Soubor vypadá jako binární. Načtěte textový log (UTF-8, Windows-1250 nebo UTF-16).',
          }
        }
      }
      const piece = decoder.decode(value, { stream: true })
      const provisional = ingest(piece, false)
      if (provisional > INPUT_LIMITS.fileMaxLines) {
        return {
          ok: false,
          code: 'too-many-lines',
          message: `Soubor má více než ${INPUT_LIMITS.fileMaxLines.toLocaleString('cs-CZ')} řádků. Rozdělte log.`,
        }
      }
    }
    const tail = decoder.decode()
    const lineCount = ingest(tail, true)
    if (lineCount > INPUT_LIMITS.fileMaxLines) {
      return {
        ok: false,
        code: 'too-many-lines',
        message: `Soubor má více než ${INPUT_LIMITS.fileMaxLines.toLocaleString('cs-CZ')} řádků. Rozdělte log.`,
      }
    }
    return okResult(lineCount)
  }

  const buf = new Uint8Array(await file.arrayBuffer())
  if (looksBinary(buf, encoding)) {
    return {
      ok: false,
      code: 'binary',
      message: 'Soubor vypadá jako binární. Načtěte textový log (UTF-8, Windows-1250 nebo UTF-16).',
    }
  }
  const text = decoder.decode(buf)
  if (text.includes('\uFFFD')) hadInvalidUtf8 = true
  const lineCount = countPhysicalLinesQuick(text)
  if (lineCount > INPUT_LIMITS.fileMaxLines) {
    return {
      ok: false,
      code: 'too-many-lines',
      message: `Soubor má více než ${INPUT_LIMITS.fileMaxLines.toLocaleString('cs-CZ')} řádků. Rozdělte log.`,
    }
  }
  return okResult(lineCount)
}

export function preflightPaste(text: string): PreflightResult {
  if (!text) {
    return { ok: false, code: 'empty', message: 'Vložte neprázdný text logu.' }
  }
  const byteLength = utf8ByteLength(text)
  if (byteLength > INPUT_LIMITS.pasteMaxBytes) {
    return {
      ok: false,
      code: 'too-large-paste',
      message: `Vložený text má ${(byteLength / BYTES_PER_MIB).toFixed(1)} MiB. Paste limit je ${INPUT_LIMITS.pasteMaxBytes / BYTES_PER_MIB} MiB — uložte obsah jako soubor a otevřete jej přes „Vybrat soubor“.`,
    }
  }
  const lineCount = countPhysicalLinesQuick(text)
  if (lineCount > INPUT_LIMITS.fileMaxLines) {
    return {
      ok: false,
      code: 'too-many-lines',
      message: `Text má více než ${INPUT_LIMITS.fileMaxLines.toLocaleString('cs-CZ')} řádků.`,
    }
  }
  return {
    ok: true,
    mode: classifyMode(byteLength, lineCount),
    byteLength,
    lineCount,
    hadInvalidUtf8: text.includes('\uFFFD'),
    sourceEncoding: 'utf-8',
    encodingConfidence: 'high',
    encodingCandidates: ['utf-8'],
  }
}

/** 1-based line numbers whose UTF-8 byte length exceeds the oversized threshold. */
export function findOversizedLines(
  text: string,
  threshold = INPUT_LIMITS.oversizedLineBytes,
): number[] {
  const out: number[] = []
  let line = 1
  let start = 0
  for (let i = 0; i <= text.length; i++) {
    const atEnd = i === text.length
    const c = atEnd ? -1 : text.charCodeAt(i)
    const isBreak = c === 10 || c === 13 || atEnd
    if (!isBreak) continue
    const slice = text.slice(start, i)
    if (slice.length > 0 && utf8ByteLength(slice) > threshold) out.push(line)
    if (c === 13 && text.charCodeAt(i + 1) === 10) i++
    start = i + 1
    line++
    if (atEnd) break
  }
  return out
}
