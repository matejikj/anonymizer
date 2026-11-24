/**
 * Visible-range replacement decorations for the anonymized pane (ARCHITECTURE §4 / §7.5).
 */

import {
  Decoration,
  type DecorationSet,
  EditorView,
  ViewPlugin,
  type ViewUpdate,
  WidgetType,
} from '@codemirror/view'
import { StateEffect } from '@codemirror/state'
import type { PackedMatchIndex } from '../../domain/types.ts'
import { matchesOverlapping } from '../../engine/packedMatchIndex.ts'
import type { ReplacementPlan } from '../../engine/transform.ts'
import { transformSlice } from '../../engine/transform.ts'

/** Dispatch to force visible-range decorations to rebuild after a plan toggle. */
export const refreshAnonEffect = StateEffect.define<null>()

class ReplacementWidget extends WidgetType {
  private readonly text: string

  constructor(text: string) {
    super()
    this.text = text
  }

  override eq(other: ReplacementWidget): boolean {
    return other.text === this.text
  }

  override toDOM(): HTMLElement {
    const span = document.createElement('span')
    span.className = 'cm-anon-replacement'
    span.textContent = this.text
    span.dataset.anon = '1'
    return span
  }

  override ignoreEvent(): boolean {
    return false
  }
}

const OVERSCAN = 2_000

export function createAnonymizedViewportPlugin(
  getIndex: () => PackedMatchIndex | null,
  getPlan: () => ReplacementPlan | null,
) {
  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet

      constructor(view: EditorView) {
        this.decorations = this.build(view)
      }

      update(update: ViewUpdate) {
        const planChanged = update.transactions.some((tr) =>
          tr.effects.some((e) => e.is(refreshAnonEffect)),
        )
        if (
          planChanged ||
          update.docChanged ||
          update.viewportChanged ||
          update.geometryChanged
        ) {
          this.decorations = this.build(update.view)
        }
      }

      build(view: EditorView): DecorationSet {
        const index = getIndex()
        const plan = getPlan()
        if (!index || !plan || index.starts.length === 0) return Decoration.none

        const ranges: Array<{ from: number; to: number }> = []
        const decoList: ReturnType<typeof Decoration.replace>[] = []
        for (const range of view.visibleRanges) {
          const from = Math.max(0, range.from - OVERSCAN)
          const to = Math.min(view.state.doc.length, range.to + OVERSCAN)
          const ids = matchesOverlapping(index, from, to)
          for (const id of ids) {
            const replacement = plan.replacements[id]
            if (replacement == null) continue
            const start = index.starts[id]!
            const end = start + index.lengths[id]!
            if (end > view.state.doc.length) continue
            ranges.push({ from: start, to: end })
            decoList.push(
              Decoration.replace({
                widget: new ReplacementWidget(replacement),
                inclusive: false,
              }),
            )
          }
        }
        const order = ranges.map((_, i) => i).sort((a, b) => {
          const ra = ranges[a]!
          const rb = ranges[b]!
          return ra.from - rb.from || ra.to - rb.to
        })
        return Decoration.set(
          order.map((i) => decoList[i]!.range(ranges[i]!.from, ranges[i]!.to)),
          true,
        )
      }
    },
    { decorations: (v) => v.decorations },
  )
}

export function createAnonymizedSecurityExtensions(options: {
  getOriginal: () => string
  getIndex: () => PackedMatchIndex | null
  getPlan: () => ReplacementPlan | null
  allowSelectionCopy: boolean
}) {
  return [
    EditorView.domEventHandlers({
      copy(event, view) {
        if (!options.allowSelectionCopy) {
          event.preventDefault()
          return true
        }
        const sel = view.state.selection.main
        if (sel.empty) return false
        const index = options.getIndex()
        const plan = options.getPlan()
        if (!index || !plan) {
          event.preventDefault()
          return true
        }
        const text = transformSlice(options.getOriginal(), sel.from, sel.to, index, plan)
        event.clipboardData?.setData('text/plain', text)
        event.preventDefault()
        return true
      },
      cut(event) {
        event.preventDefault()
        return true
      },
      dragstart(event, view) {
        const sel = view.state.selection.main
        if (!sel.empty && event.dataTransfer) {
          if (!options.allowSelectionCopy) {
            event.preventDefault()
            return true
          }
          const index = options.getIndex()
          const plan = options.getPlan()
          if (!index || !plan) {
            event.preventDefault()
            return true
          }
          event.dataTransfer.setData(
            'text/plain',
            transformSlice(options.getOriginal(), sel.from, sel.to, index, plan),
          )
          event.preventDefault()
          return true
        }
        return false
      },
    }),
  ]
}

/** Request a decoration rebuild after plan toggle (Krok 6). */
export function refreshAnonymizedDecorations(view: EditorView): void {
  view.dispatch({
    effects: [],
    annotations: [],
  })
  // Force viewport plugin rebuild via a no-op scroll nudge
  view.requestMeasure()
}

/**
 * Mark active match spans on the original pane so sensitive values are visible
 * there as well as (replaced) on the anonymized pane.
 */
export function createOriginalMatchHighlightPlugin(
  getIndex: () => PackedMatchIndex | null,
  getPlan: () => ReplacementPlan | null,
) {
  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet

      constructor(view: EditorView) {
        this.decorations = this.build(view)
      }

      update(update: ViewUpdate) {
        const planChanged = update.transactions.some((tr) =>
          tr.effects.some((e) => e.is(refreshAnonEffect)),
        )
        if (
          planChanged ||
          update.docChanged ||
          update.viewportChanged ||
          update.geometryChanged
        ) {
          this.decorations = this.build(update.view)
        }
      }

      build(view: EditorView): DecorationSet {
        const index = getIndex()
        const plan = getPlan()
        if (!index || !plan || index.starts.length === 0) return Decoration.none

        const ranges: Array<{ from: number; to: number }> = []
        const decoList: ReturnType<typeof Decoration.mark>[] = []
        for (const range of view.visibleRanges) {
          const from = Math.max(0, range.from - OVERSCAN)
          const to = Math.min(view.state.doc.length, range.to + OVERSCAN)
          const ids = matchesOverlapping(index, from, to)
          for (const id of ids) {
            if (plan.replacements[id] == null) continue
            const start = index.starts[id]!
            const end = start + index.lengths[id]!
            if (end > view.state.doc.length || start >= end) continue
            ranges.push({ from: start, to: end })
            decoList.push(Decoration.mark({ class: 'cm-original-match' }))
          }
        }
        const order = ranges.map((_, i) => i).sort((a, b) => {
          const ra = ranges[a]!
          const rb = ranges[b]!
          return ra.from - rb.from || ra.to - rb.to
        })
        return Decoration.set(
          order.map((i) => decoList[i]!.range(ranges[i]!.from, ranges[i]!.to)),
          true,
        )
      }
    },
    { decorations: (v) => v.decorations },
  )
}
