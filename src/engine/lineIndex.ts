/**
 * Physical line index over an immutable original string.
 * Lines are 1-based. Supports LF, CRLF and lone CR.
 */
export interface LineIndex {
  readonly text: string
  readonly lineCount: number
  /** Start offset (inclusive) of each 1-based line. Index 0 unused. */
  readonly lineStarts: readonly number[]
  lineAt(offset: number): number
  /** [start, end) of line content without its terminating newline. */
  lineContentRange(line: number): { start: number; end: number }
  lineText(line: number): string
}

export function buildLineIndex(text: string): LineIndex {
  const lineStarts: number[] = [0, 0]
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (c === 10) {
      lineStarts.push(i + 1)
    } else if (c === 13) {
      if (text.charCodeAt(i + 1) === 10) {
        lineStarts.push(i + 2)
        i++
      } else {
        lineStarts.push(i + 1)
      }
    }
  }
  const lineCount = lineStarts.length - 1

  function lineAt(offset: number): number {
    if (offset < 0) offset = 0
    if (offset > text.length) offset = text.length
    // largest lineStarts[line] <= offset
    let lo = 1
    let hi = lineCount
    while (lo < hi) {
      const mid = (lo + hi + 1) >>> 1
      if (lineStarts[mid]! <= offset) lo = mid
      else hi = mid - 1
    }
    return lo
  }

  function lineContentRange(lineNo: number): { start: number; end: number } {
    if (lineNo < 1 || lineNo > lineCount) {
      // T03: avoid `${line}` template shape (guard treats bare `line` as identity-bearing).
      throw new Error(`Neplatné číslo řádku: ${lineNo}`)
    }
    const start = lineStarts[lineNo]!
    if (lineNo === lineCount) return { start, end: text.length }
    const nextStart = lineStarts[lineNo + 1]!
    // Trim terminating newline(s) before next line start.
    let end = nextStart
    if (end > start && text.charCodeAt(end - 1) === 10) end--
    if (end > start && text.charCodeAt(end - 1) === 13) end--
    return { start, end }
  }

  function lineText(line: number): string {
    const { start, end } = lineContentRange(line)
    return text.slice(start, end)
  }

  return { text, lineCount, lineStarts, lineAt, lineContentRange, lineText }
}

/** Split preserving line endings as separate pieces for exact rejoin. */
export function splitPhysicalLines(text: string): { lines: string[]; endings: string[] } {
  const lines: string[] = []
  const endings: string[] = []
  let start = 0
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (c === 13 && text.charCodeAt(i + 1) === 10) {
      lines.push(text.slice(start, i))
      endings.push('\r\n')
      i++
      start = i + 1
    } else if (c === 10 || c === 13) {
      lines.push(text.slice(start, i))
      endings.push(c === 10 ? '\n' : '\r')
      start = i + 1
    }
  }
  lines.push(text.slice(start))
  endings.push('')
  return { lines, endings }
}

export function joinPhysicalLines(lines: string[], endings: string[]): string {
  if (lines.length !== endings.length) {
    throw new Error('lines/endings length mismatch')
  }
  let out = ''
  for (let i = 0; i < lines.length; i++) {
    out += lines[i]! + endings[i]!
  }
  return out
}
