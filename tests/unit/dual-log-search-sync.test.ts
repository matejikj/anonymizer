/**
 * Stage 3 — DualLogView search sync contracts (highlight clear, active index, debounce gen).
 */

/** @vitest-environment jsdom */

import { describe, expect, it, vi } from 'vitest'
import {
  createSearchGeneration,
  paneToRerevealAfterClear,
  resolveActiveMatchIndex,
  shouldClearHighlights,
  shouldNavigateToActiveMatch,
} from '../../src/features/workspace/dualLogSearchSync.ts'

describe('shouldClearHighlights', () => {
  it('keeps highlights when original is empty but anonymized query is active', () => {
    expect(shouldClearHighlights('', 'alias')).toBe(false)
  })

  it('keeps highlights when anonymized is empty but original query is active', () => {
    expect(shouldClearHighlights('10.0.0.1', '')).toBe(false)
  })

  it('clears highlights only when both queries are empty', () => {
    expect(shouldClearHighlights('', '')).toBe(true)
    expect(shouldClearHighlights('a', 'b')).toBe(false)
  })
})

describe('resolveActiveMatchIndex', () => {
  const matches = [
    { from: 0, to: 2 },
    { from: 10, to: 12 },
    { from: 20, to: 25 },
  ]

  it('returns -1 when there are no matches', () => {
    expect(resolveActiveMatchIndex([], 1, matches)).toBe(-1)
  })

  it('preserves the previously active span when it still exists after recompute', () => {
    expect(resolveActiveMatchIndex(matches, 1, matches)).toBe(1)
  })

  it('falls back to first match when the previous active span disappeared', () => {
    const next = [
      { from: 0, to: 2 },
      { from: 20, to: 25 },
    ]
    expect(resolveActiveMatchIndex(next, 1, matches)).toBe(0)
  })

  it('does not reset active match merely because another pane query changed', () => {
    // Same matches + same previous active → index unchanged (anonQuery change never feeds here).
    expect(resolveActiveMatchIndex(matches, 2, matches)).toBe(2)
    expect(shouldNavigateToActiveMatch(matches, 2, { queryChanged: false, caseChanged: false })).toBe(
      false,
    )
  })

  it('navigates after case-sensitivity change', () => {
    expect(shouldNavigateToActiveMatch(matches, 0, { queryChanged: false, caseChanged: true })).toBe(
      true,
    )
  })
})

describe('createSearchGeneration — rapid typing / stale timeout', () => {
  it('ignores callbacks from superseded debounce generations', () => {
    const gen = createSearchGeneration()
    const first = gen.next()
    const second = gen.next()
    expect(gen.isCurrent(first)).toBe(false)
    expect(gen.isCurrent(second)).toBe(true)

    const published: string[] = []
    const apply = (token: number, value: string) => {
      if (!gen.isCurrent(token)) return
      published.push(value)
    }
    apply(first, 'stale')
    apply(second, 'fresh')
    expect(published).toEqual(['fresh'])
  })

  it('invalidate drops in-flight timers after session switch', () => {
    vi.useFakeTimers()
    const gen = createSearchGeneration()
    const token = gen.next()
    let applied = false
    setTimeout(() => {
      if (!gen.isCurrent(token)) return
      applied = true
    }, 150)
    gen.invalidate()
    vi.advanceTimersByTime(200)
    expect(applied).toBe(false)
    vi.useRealTimers()
  })
})

describe('paneToRerevealAfterClear', () => {
  it('re-reveals anonymized active match when original query is cleared', () => {
    expect(
      paneToRerevealAfterClear({
        clearedPane: 'original',
        originalQuery: '',
        anonQuery: 'Person',
        originalActive: -1,
        anonActive: 0,
      }),
    ).toBe('anonymized')
  })

  it('re-reveals original active match when anonymized query is cleared', () => {
    expect(
      paneToRerevealAfterClear({
        clearedPane: 'anonymized',
        originalQuery: 'host',
        anonQuery: '',
        originalActive: 1,
        anonActive: -1,
      }),
    ).toBe('original')
  })

  it('returns null when the remaining pane has no active match', () => {
    expect(
      paneToRerevealAfterClear({
        clearedPane: 'original',
        originalQuery: '',
        anonQuery: 'x',
        originalActive: -1,
        anonActive: -1,
      }),
    ).toBeNull()
  })
})

describe('DualLogView wiring (Stage 3)', () => {
  it('keeps original and anonymized search effects independent of the other query', async () => {
    const { readFileSync } = await import('node:fs')
    const { join } = await import('node:path')
    const src = readFileSync(
      join(process.cwd(), 'src/features/workspace/DualLogView.tsx'),
      'utf8',
    )
    expect(src).not.toMatch(/eslint-disable[^\n]*exhaustive-deps/)
    // Original search effect deps must not include anonQuery (and vice versa).
    expect(src).toMatch(/\}, \[originalQuery, originalCase, sessionEpoch\]\)/)
    expect(src).toMatch(/\}, \[anonQuery, anonCase, sessionEpoch\]\)/)
    // Shared clear decision reads both queries without mixing match computation.
    expect(src).toMatch(/shouldClearHighlights\(originalQuery, anonQuery\)/)
    expect(src).toMatch(/\}, \[originalQuery, anonQuery\]\)/)
  })
})
