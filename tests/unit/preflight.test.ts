import { describe, expect, it } from 'vitest'
import {
  classifyMode,
  countPhysicalLinesQuick,
  countNewlinesIncremental,
  findOversizedLines,
  preflightPaste,
} from '../../src/features/import-log/preflight.ts'
import { INPUT_LIMITS, BYTES_PER_MIB } from '../../src/features/import-log/inputLimits.ts'

describe('preflight', () => {
  it('classifies common vs large mode', () => {
    expect(classifyMode(1024, 10)).toBe('common')
    expect(classifyMode(INPUT_LIMITS.commonMaxBytes + 1, 10)).toBe('large')
    expect(classifyMode(100, INPUT_LIMITS.commonMaxLines + 1)).toBe('large')
  })

  it('rejects oversized paste', () => {
    const huge = 'x'.repeat(INPUT_LIMITS.pasteMaxBytes + 10)
    const r = preflightPaste(huge)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.code).toBe('too-large-paste')
  })

  it('accepts normal paste and counts lines', () => {
    const text = 'a\nb\nc'
    const r = preflightPaste(text)
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.lineCount).toBe(3)
      expect(r.mode).toBe('common')
    }
  })

  it('counts CRLF split across chunks', () => {
    const a = countNewlinesIncremental('hello\r', false)
    expect(a.completeLines).toBe(0)
    expect(a.pendingCr).toBe(true)
    const b = countNewlinesIncremental('\nworld\n', true)
    expect(b.completeLines).toBe(2)
  })

  it('finds oversized lines', () => {
    const long = 'y'.repeat(INPUT_LIMITS.oversizedLineBytes + 8)
    const text = `short\n${long}\nend`
    expect(findOversizedLines(text)).toEqual([2])
    expect(BYTES_PER_MIB).toBe(1024 * 1024)
    expect(countPhysicalLinesQuick(text)).toBe(3)
  })
})
