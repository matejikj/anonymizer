/**
 * Streaming decode + physical line assembly (ARCHITECTURE §8 / T43).
 * Holds only the unfinished line tail between chunks.
 * Emits canonical LF fragments and packed original line endings for export.
 * Default encoding UTF-8; override via {@link createLineAssembler}.
 */

import {
  ENDING_CR,
  ENDING_CRLF,
  ENDING_LF,
  ENDING_NONE,
} from '../export-log/lineEndings.ts'
import {
  createTextDecoder,
  type TextEncodingLabel,
} from './textEncoding.ts'

export interface LineAssemblerState {
  decoder: TextDecoder
  readonly encoding: TextEncodingLabel
  /** Unfinished physical line (no terminating newline yet). */
  lineTail: string
  /** Raw document offset of lineTail start (internal). */
  absoluteOffset: number
  processedBytes: number
  processedLines: number
  /** Next start offset in the LF-normalized document (worker + CodeMirror). */
  canonicalOffset: number
  /** Packed ENDING_* codes, one per completed physical line. */
  packedEndings: number[]
}

export interface AssembledLine {
  text: string
  /** Absolute UTF-16 start offset in the LF-normalized document. */
  start: number
  /** 1-based physical line number. */
  line: number
  /** Terminator that followed this line: '\n' | '\r\n' | '\r' | '' (EOF). */
  ending: '\n' | '\r\n' | '\r' | ''
}

export interface LinePushResult {
  lines: AssembledLine[]
  /** LF-normalized fragment to append to editor/worker for this push call. */
  lfFragment: string
}

export function createLineAssembler(
  encoding: TextEncodingLabel = 'utf-8',
): LineAssemblerState {
  return {
    decoder: createTextDecoder(encoding, { fatal: false }),
    encoding,
    lineTail: '',
    absoluteOffset: 0,
    processedBytes: 0,
    processedLines: 0,
    canonicalOffset: 0,
    packedEndings: [],
  }
}

function endingToCode(ending: AssembledLine['ending']): number {
  switch (ending) {
    case '\r\n':
      return ENDING_CRLF
    case '\r':
      return ENDING_CR
    case '\n':
      return ENDING_LF
    default:
      return ENDING_NONE
  }
}

function appendCanonicalLine(
  state: LineAssemblerState,
  text: string,
  ending: AssembledLine['ending'],
  final: boolean,
): string {
  state.packedEndings.push(endingToCode(ending))
  if (ending !== '') {
    state.canonicalOffset += text.length + 1
    return text + '\n'
  }
  if (final) {
    state.canonicalOffset += text.length
    return text
  }
  return ''
}

/** Snapshot packed endings collected so far (copy). */
export function takePackedLineEndings(state: LineAssemblerState): Uint8Array {
  return new Uint8Array(state.packedEndings)
}

/**
 * Feed a byte view (must respect byteOffset/byteLength of the backing buffer).
 * Returns newly completed physical lines and the LF fragment for this push.
 */
export function pushBytes(
  state: LineAssemblerState,
  bytes: Uint8Array,
  final: boolean,
): LinePushResult {
  state.processedBytes += bytes.byteLength
  const piece = state.decoder.decode(bytes, { stream: !final })
  return pushText(state, piece, final)
}

/** Feed a UTF-16 string slice (paste / canonical re-send path). */
export function pushText(
  state: LineAssemblerState,
  piece: string,
  final: boolean,
): LinePushResult {
  const combined = state.lineTail + piece
  const out: AssembledLine[] = []
  let lfFragment = ''
  let cursor = 0
  let lineStartAbs = state.absoluteOffset

  for (let i = 0; i < combined.length; i++) {
    const c = combined.charCodeAt(i)
    if (c === 13 /* CR */) {
      const next = combined.charCodeAt(i + 1)
      if (next === 10) {
        const text = combined.slice(cursor, i)
        state.processedLines += 1
        const ending = '\r\n' as const
        const start = state.canonicalOffset
        out.push({ text, start, line: state.processedLines, ending })
        lfFragment += appendCanonicalLine(state, text, ending, false)
        i++
        cursor = i + 1
        lineStartAbs += text.length + 2
      } else if (Number.isNaN(next)) {
        if (!final) break
        const text = combined.slice(cursor, i)
        state.processedLines += 1
        const ending = '\r' as const
        const start = state.canonicalOffset
        out.push({ text, start, line: state.processedLines, ending })
        lfFragment += appendCanonicalLine(state, text, ending, true)
        cursor = i + 1
        lineStartAbs += text.length + 1
      } else {
        const text = combined.slice(cursor, i)
        state.processedLines += 1
        const ending = '\r' as const
        const start = state.canonicalOffset
        out.push({ text, start, line: state.processedLines, ending })
        lfFragment += appendCanonicalLine(state, text, ending, false)
        cursor = i + 1
        lineStartAbs += text.length + 1
      }
    } else if (c === 10 /* LF */) {
      const text = combined.slice(cursor, i)
      state.processedLines += 1
      const ending = '\n' as const
      const start = state.canonicalOffset
      out.push({ text, start, line: state.processedLines, ending })
      lfFragment += appendCanonicalLine(state, text, ending, false)
      cursor = i + 1
      lineStartAbs += text.length + 1
    }
  }

  if (final) {
    const text = combined.slice(cursor)
    state.processedLines += 1
    const ending = '' as const
    const start = state.canonicalOffset
    out.push({ text, start, line: state.processedLines, ending })
    lfFragment += appendCanonicalLine(state, text, ending, true)
    state.lineTail = ''
    state.absoluteOffset = lineStartAbs + text.length
  } else {
    state.lineTail = combined.slice(cursor)
    state.absoluteOffset = lineStartAbs
  }

  return { lines: out, lfFragment }
}

const sharedEncoder = new TextEncoder()

/** UTF-8 byte length of a JS string (for paste limit accounting). */
export function utf8ByteLength(text: string): number {
  return sharedEncoder.encode(text).byteLength
}
