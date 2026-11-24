import { describe, expect, it } from 'vitest'
import { resolveOverlaps } from '../../src/engine/resolveOverlaps.ts'
import type { RawMatch } from '../../src/domain/types.ts'

function m(partial: Partial<RawMatch> & Pick<RawMatch, 'start' | 'end' | 'priority'>): RawMatch {
  return {
    line: 1,
    category: 'custom',
    original: 'x'.repeat(partial.end - partial.start),
    normalized: 'x'.repeat(partial.end - partial.start),
    detectorId: partial.detectorId ?? 't',
    ruleId: partial.ruleId,
    confidence: 1,
    ...partial,
  }
}

describe('resolveOverlaps', () => {
  it('keeps higher priority over nested lower', () => {
    const resolved = resolveOverlaps([
      m({ start: 0, end: 10, priority: 40, detectorId: 'outer', original: 'abcdefghij', normalized: 'abcdefghij', category: 'hostname' }),
      m({ start: 2, end: 5, priority: 90, detectorId: 'inner', original: 'cde', normalized: 'cde', category: 'email' }),
    ])
    expect(resolved).toHaveLength(1)
    expect(resolved[0]!.detectorId).toBe('inner')
  })

  it('on equal priority prefers longer match', () => {
    const resolved = resolveOverlaps([
      m({ start: 0, end: 3, priority: 50, detectorId: 'short', original: 'abc', normalized: 'abc', category: 'ip' }),
      m({ start: 0, end: 5, priority: 50, detectorId: 'long', original: 'abcde', normalized: 'abcde', category: 'ip' }),
    ])
    expect(resolved[0]!.detectorId).toBe('long')
  })

  it('on equal priority and length prefers lower start then detectorId', () => {
    const resolved = resolveOverlaps([
      m({ start: 5, end: 8, priority: 50, detectorId: 'b', original: 'xxx', normalized: 'xxx', category: 'ip' }),
      m({ start: 0, end: 3, priority: 50, detectorId: 'a', original: 'xxx', normalized: 'xxx', category: 'ip' }),
    ])
    expect(resolved.map((x) => x.start)).toEqual([0, 5])
  })

  it('partial overlap: winner removes loser', () => {
    const resolved = resolveOverlaps([
      m({ start: 0, end: 5, priority: 60, detectorId: 'left', original: 'aaaaa', normalized: 'aaaaa', category: 'user-id' }),
      m({ start: 3, end: 8, priority: 50, detectorId: 'right', original: 'bbbbb', normalized: 'bbbbb', category: 'ip' }),
    ])
    expect(resolved).toHaveLength(1)
    expect(resolved[0]!.detectorId).toBe('left')
  })

  it('identical span: priority then detectorId', () => {
    const resolved = resolveOverlaps([
      m({ start: 0, end: 4, priority: 1000, detectorId: 'custom.rule', ruleId: 'z', original: 'test', normalized: 'test', category: 'custom' }),
      m({ start: 0, end: 4, priority: 50, detectorId: 'builtin.ip', original: 'test', normalized: 'test', category: 'ip' }),
    ])
    expect(resolved).toHaveLength(1)
    expect(resolved[0]!.detectorId).toBe('custom.rule')
  })

  it('result is sorted by start and non-overlapping', () => {
    const resolved = resolveOverlaps([
      m({ start: 10, end: 12, priority: 50, detectorId: 'b', original: 'ab', normalized: 'ab', category: 'ip' }),
      m({ start: 0, end: 2, priority: 50, detectorId: 'a', original: 'cd', normalized: 'cd', category: 'ip' }),
      m({ start: 4, end: 7, priority: 50, detectorId: 'c', original: 'efg', normalized: 'efg', category: 'ip' }),
    ])
    expect(resolved.map((x) => x.start)).toEqual([0, 4, 10])
  })

  it('resolves conflicts within a line and never merges matches across different lines', () => {
    const resolved = resolveOverlaps([
      m({ start: 100, end: 105, priority: 90, line: 2, detectorId: 'inner', original: 'aaaaa', normalized: 'aaaaa', category: 'email' }),
      m({ start: 100, end: 110, priority: 40, line: 2, detectorId: 'outer', original: 'bbbbbbbbbb', normalized: 'bbbbbbbbbb', category: 'hostname' }),
      // Same absolute range reused on a different line — must be resolved independently, not as a duplicate.
      m({ start: 100, end: 105, priority: 90, line: 3, detectorId: 'inner', original: 'aaaaa', normalized: 'aaaaa', category: 'email' }),
    ])
    expect(resolved).toHaveLength(2)
    expect(resolved.map((r) => r.line).sort()).toEqual([2, 3])
    expect(resolved.every((r) => r.detectorId === 'inner')).toBe(true)
  })

  it('stays fast for many matches spread across many lines (regression: O(n²) global conflict scan)', () => {
    const raw: RawMatch[] = []
    // 20,000 lines, 3 matches each = 60,000 total raw matches, none overlapping across lines.
    for (let line = 1; line <= 20_000; line++) {
      const base = line * 100
      raw.push(m({ start: base, end: base + 5, priority: 50, line, detectorId: 'a', category: 'ip' }))
      raw.push(m({ start: base + 10, end: base + 15, priority: 50, line, detectorId: 'b', category: 'hostname' }))
      raw.push(m({ start: base + 20, end: base + 25, priority: 50, line, detectorId: 'c', category: 'user-id' }))
    }
    const start = performance.now()
    const resolved = resolveOverlaps(raw)
    const elapsedMs = performance.now() - start
    expect(resolved).toHaveLength(60_000)
    expect(elapsedMs).toBeLessThan(1000)
  })
})
