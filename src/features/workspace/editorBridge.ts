/**
 * Imperative bridge between DualLogView and toolbar / tests.
 */

import type { EditorView } from '@codemirror/view'
import type { SyncControllers } from './useSynchronizedEditors.ts'

export interface DualLogBridge {
  left: EditorView
  right: EditorView
  sync: SyncControllers
  setWrap: (wrap: boolean) => void
  getWrap: () => boolean
  /** Jump both panes so match index is visible; returns physical line. */
  jumpToMatchIndex: (matchIndex: number) => number
  /** Highlight a physical line in both panes. */
  highlightLine: (line: number) => void
  /** Force anonymized pane to rebuild decorations after plan change. */
  refreshDecorations: () => void
  getTopLine: () => number
  /** Focus + select the log-search input (Ctrl/Cmd+F target). */
  focusSearch: () => void
  destroy: () => void
}

let bridge: DualLogBridge | null = null

export function registerDualLogBridge(next: DualLogBridge | null): void {
  bridge = next
}

export function getDualLogBridge(): DualLogBridge | null {
  return bridge
}
