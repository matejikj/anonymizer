/**
 * Dual-pane search synchronization helpers (Stage 3).
 * Keep highlight clear / active-index decisions outside debounce closures so
 * original and anonymized queries cannot stale-cross each other.
 */

export interface TextMatch {
  readonly from: number
  readonly to: number
}

/** Clear cross-pane highlights only when both search boxes are empty. */
export function shouldClearHighlights(originalQuery: string, anonQuery: string): boolean {
  return originalQuery.length === 0 && anonQuery.length === 0
}

/**
 * After recomputing matches for one pane, prefer keeping the previously active
 * span if it still exists; otherwise land on the first match (or none).
 */
export function resolveActiveMatchIndex(
  matches: readonly TextMatch[],
  previousActive: number,
  previousMatches: readonly TextMatch[],
): number {
  if (matches.length === 0) return -1
  if (previousActive >= 0 && previousActive < previousMatches.length) {
    const prev = previousMatches[previousActive]!
    const found = matches.findIndex((m) => m.from === prev.from && m.to === prev.to)
    if (found >= 0) return found
  }
  return 0
}

/** Whether a search result update should navigate to the active match. */
export function shouldNavigateToActiveMatch(
  matches: readonly TextMatch[],
  activeIndex: number,
  opts: { readonly queryChanged: boolean; readonly caseChanged: boolean },
): boolean {
  if (matches.length === 0 || activeIndex < 0) return false
  // Fresh query or case flip always reveals the resolved active hit.
  if (opts.queryChanged || opts.caseChanged) return true
  return false
}

/**
 * Monotonic debounce generation: ignore a timeout callback if a newer search
 * was scheduled (rapid typing / unmount / session switch).
 */
export function createSearchGeneration() {
  let current = 0
  return {
    next(): number {
      current += 1
      return current
    },
    isCurrent(token: number): boolean {
      return token === current
    },
    invalidate(): void {
      current += 1
    },
  }
}

export type SearchPane = 'original' | 'anonymized'

/**
 * Decide which pane (if any) should re-reveal its active match after the other
 * pane's query was cleared. Prevents wiping a still-valid highlight.
 */
export function paneToRerevealAfterClear(opts: {
  readonly clearedPane: SearchPane
  readonly originalQuery: string
  readonly anonQuery: string
  readonly originalActive: number
  readonly anonActive: number
}): SearchPane | null {
  if (opts.clearedPane === 'original') {
    if (opts.anonQuery.length > 0 && opts.anonActive >= 0) return 'anonymized'
    return null
  }
  if (opts.originalQuery.length > 0 && opts.originalActive >= 0) return 'original'
  return null
}
