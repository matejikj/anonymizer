/**
 * Selection history for Alt+←/→ navigation (step 2).
 */

export interface SelectionSnapshot {
  readonly packetIndex: number
  readonly fieldPath: string | null
  readonly byteOffset: number | null
}

export function pushSelectionHistory(
  history: readonly SelectionSnapshot[],
  index: number,
  snapshot: SelectionSnapshot,
  max = 50,
): { history: SelectionSnapshot[]; index: number } {
  const trimmed = history.slice(0, index + 1)
  const last = trimmed[trimmed.length - 1]
  if (
    last &&
    last.packetIndex === snapshot.packetIndex &&
    last.fieldPath === snapshot.fieldPath &&
    last.byteOffset === snapshot.byteOffset
  ) {
    return { history: [...trimmed], index: trimmed.length - 1 }
  }
  const next = [...trimmed, snapshot]
  if (next.length > max) next.shift()
  return { history: next, index: next.length - 1 }
}

export function navigateSelectionHistory(
  history: readonly SelectionSnapshot[],
  index: number,
  direction: -1 | 1,
): { snapshot: SelectionSnapshot | null; index: number } {
  if (history.length === 0) return { snapshot: null, index: -1 }
  const nextIndex = index + direction
  if (nextIndex < 0 || nextIndex >= history.length) {
    return { snapshot: null, index }
  }
  return { snapshot: history[nextIndex]!, index: nextIndex }
}
