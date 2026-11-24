import type { RawMatch, ResolvedMatch } from './types.ts'

export function assertNoNewline(value: string, label: string): void {
  if (value.includes('\n') || value.includes('\r')) {
    throw new Error(`${label} nesmí obsahovat znak nového řádku`)
  }
}

export function assertNonEmptyMatch(start: number, end: number): void {
  if (!(start < end)) {
    throw new Error('Match musí mít kladnou délku')
  }
}

export function assertMatchBounds(text: string, start: number, end: number): void {
  if (!(0 <= start && start < end && end <= text.length)) {
    // T03: do not interpolate the document buffer — lengths/offsets only.
    const len = text.length
    throw new Error(`Match mimo rozsah textu: [${start}, ${end}) length=${len}`)
  }
  const slice = text.slice(start, end)
  if (slice.includes('\n') || slice.includes('\r')) {
    throw new Error('Match nesmí obsahovat CR/LF')
  }
}

export function assertResolvedNonOverlapping(matches: ResolvedMatch[]): void {
  for (let i = 1; i < matches.length; i++) {
    const prev = matches[i - 1]!
    const cur = matches[i]!
    if (cur.start < prev.end) {
      throw new Error(
        `Překrývající se resolved match: [${prev.start},${prev.end}) a [${cur.start},${cur.end})`,
      )
    }
    if (cur.start < prev.start) {
      throw new Error('Resolved matches musí být seřazené podle start')
    }
  }
}

export function assertSameLineCount(original: string, output: string): void {
  const a = countPhysicalLines(original)
  const b = countPhysicalLines(output)
  if (a !== b) {
    throw new Error(`Počet fyzických řádků se změnil: ${a} → ${b}`)
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
    throw new Error('RawMatch.original neodpovídá text.slice(start, end)')
  }
}
