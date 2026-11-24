import type { RawMatch, ResolvedMatch } from './types.ts'

export function assertNoNewline(value: string, label: string): void {
  if (value.includes('\n') || value.includes('\r')) {
    throw new Error(`${label} must not contain a newline character`)
  }
}

export function assertNonEmptyMatch(start: number, end: number): void {
  if (!(start < end)) {
    throw new Error('Match must have positive length')
  }
}

export function assertMatchBounds(text: string, start: number, end: number): void {
  if (!(0 <= start && start < end && end <= text.length)) {
    // T03: do not interpolate the document buffer — lengths/offsets only.
    const len = text.length
    throw new Error(`Match out of text bounds: [${start}, ${end}) length=${len}`)
  }
  const slice = text.slice(start, end)
  if (slice.includes('\n') || slice.includes('\r')) {
    throw new Error('Match must not contain CR/LF')
  }
}

export function assertResolvedNonOverlapping(matches: ResolvedMatch[]): void {
  for (let i = 1; i < matches.length; i++) {
    const prev = matches[i - 1]!
    const cur = matches[i]!
    if (cur.start < prev.end) {
      throw new Error(
        `Overlapping resolved matches: [${prev.start},${prev.end}) and [${cur.start},${cur.end})`,
      )
    }
    if (cur.start < prev.start) {
      throw new Error('Resolved matches must be sorted by start')
    }
  }
}

export function assertSameLineCount(original: string, output: string): void {
  const a = countPhysicalLines(original)
  const b = countPhysicalLines(output)
  if (a !== b) {
    throw new Error(`Physical line count changed: ${a} → ${b}`)
  }
}

export function countPhysicalLines(text: string): number {
  if (text.length === 0) return 1
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

export function validateRawMatch(text: string, match: RawMatch): void {
  assertMatchBounds(text, match.start, match.end)
  assertNonEmptyMatch(match.start, match.end)
  assertNoNewline(match.original, 'original')
  assertNoNewline(match.normalized, 'normalized')
  if (match.original !== text.slice(match.start, match.end)) {
    throw new Error('RawMatch.original does not match text.slice(start, end)')
  }
}
