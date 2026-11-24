import { describe, expect, it } from 'vitest'
import { buildLineIndex, splitPhysicalLines, joinPhysicalLines } from '../../src/engine/lineIndex.ts'
import { countPhysicalLines } from '../../src/domain/invariants.ts'

describe('lineIndex', () => {
  it('indexes LF lines as 1-based', () => {
    const text = 'a\nb\nc'
    const idx = buildLineIndex(text)
    expect(idx.lineCount).toBe(3)
    expect(idx.lineAt(0)).toBe(1)
    expect(idx.lineAt(2)).toBe(2)
    expect(idx.lineText(2)).toBe('b')
  })

  it('handles CRLF and lone CR', () => {
    const text = 'a\r\nb\rc'
    const idx = buildLineIndex(text)
    expect(idx.lineCount).toBe(3)
    expect(idx.lineText(1)).toBe('a')
    expect(idx.lineText(2)).toBe('b')
    expect(idx.lineText(3)).toBe('c')
  })

  it('round-trips split/join preserving endings', () => {
    const text = 'one\r\ntwo\nthree\rfour'
    const { lines, endings } = splitPhysicalLines(text)
    expect(joinPhysicalLines(lines, endings)).toBe(text)
    expect(countPhysicalLines(text)).toBe(4)
  })
})
