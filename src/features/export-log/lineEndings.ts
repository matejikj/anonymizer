/**
 * Packed line-ending index for export (ARCHITECTURE §7.5 / Krok 9).
 * Editor works on LF; export restores original LF/CRLF/CR.
 */

import { splitPhysicalLines, joinPhysicalLines } from '../../engine/lineIndex.ts'

export const ENDING_LF = 0
export const ENDING_CRLF = 1
export const ENDING_CR = 2
export const ENDING_NONE = 3

export function packLineEndingsFromText(text: string): Uint8Array {
  const { endings } = splitPhysicalLines(text)
  const out = new Uint8Array(endings.length)
  for (let i = 0; i < endings.length; i++) {
    const e = endings[i]!
    out[i] =
      e === '\r\n' ? ENDING_CRLF : e === '\r' ? ENDING_CR : e === '\n' ? ENDING_LF : ENDING_NONE
  }
  return out
}

export function unpackEnding(code: number): string {
  switch (code) {
    case ENDING_CRLF:
      return '\r\n'
    case ENDING_CR:
      return '\r'
    case ENDING_LF:
      return '\n'
    default:
      return ''
  }
}

/** Apply stored endings to an LF-normalized anonymized string. */
export function applyPackedLineEndings(lfText: string, endings: Uint8Array): string {
  const { lines } = splitPhysicalLines(lfText.replace(/\r\n/g, '\n').replace(/\r/g, '\n'))
  const endingStrs: string[] = []
  for (let i = 0; i < lines.length; i++) {
    endingStrs.push(i < endings.length ? unpackEnding(endings[i]!) : i === lines.length - 1 ? '' : '\n')
  }
  // splitPhysicalLines on LF text: if text ends with \n, last line is '' with ending ''
  while (endingStrs.length < lines.length) endingStrs.push('')
  if (endingStrs.length > lines.length) endingStrs.length = lines.length
  return joinPhysicalLines(lines, endingStrs)
}

export function sliceEndingWindow(
  endings: Uint8Array,
  fromLine: number,
  lineCount: number,
): { endings: ArrayBuffer; lineCount: number } {
  const start = Math.max(0, fromLine - 1)
  const slice = endings.slice(start, start + lineCount)
  return {
    endings: slice.buffer.slice(slice.byteOffset, slice.byteOffset + slice.byteLength),
    lineCount: slice.length,
  }
}
