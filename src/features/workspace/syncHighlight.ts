/**
 * Cross-pane line + match highlight decorations.
 */

import { StateEffect, StateField } from '@codemirror/state'
import { Decoration, EditorView, type DecorationSet } from '@codemirror/view'

export const setHighlightEffect = StateEffect.define<{
  line: number
  from?: number
  to?: number
} | null>()

export const highlightField = StateField.define<DecorationSet>({
  create() {
    return Decoration.none
  },
  update(deco, tr) {
    for (const e of tr.effects) {
      if (e.is(setHighlightEffect)) {
        if (!e.value) return Decoration.none
        const { line, from, to } = e.value
        const docLine = tr.state.doc.line(Math.min(Math.max(1, line), tr.state.doc.lines))
        const ranges = [
          Decoration.line({ class: 'cm-sync-line' }).range(docLine.from),
        ]
        if (from != null && to != null && from < to && to <= tr.state.doc.length) {
          ranges.push(
            Decoration.mark({ class: 'cm-sync-match' }).range(from, to),
          )
        }
        return Decoration.set(ranges, true)
      }
    }
    return deco.map(tr.changes)
  },
  provide: (f) => EditorView.decorations.from(f),
})

export function dispatchHighlight(
  view: EditorView,
  line: number,
  from?: number,
  to?: number,
): void {
  view.dispatch({
    effects: setHighlightEffect.of({ line, from, to }),
  })
}

export function clearHighlight(view: EditorView): void {
  view.dispatch({ effects: setHighlightEffect.of(null) })
}
