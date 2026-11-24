/**
 * Dual-pane scroll sync — line-anchor vertical + column-mapped horizontal
 * (ARCHITECTURE §4.2 / §4.3 / Krok 5).
 *
 * Important: programmatic follower scrolls must not become a new sync leader,
 * otherwise the anonymized pane (widget heights) can snap the original back to
 * line 1 after the user finishes scrolling.
 */

import { EditorView } from '@codemirror/view'
import type { PackedMatchIndex } from '../../domain/types.ts'
import type { ReplacementPlan } from '../../engine/transform.ts'
import { buildLineColumnMap, mapPhysicalLine } from '../../engine/columnMap.ts'

export interface SyncOptions {
  getWrap: () => boolean
  getPacked: () => PackedMatchIndex | null
  getPlan: () => ReplacementPlan | null
  /** Which pane is the "original" (left) for column mapping direction. */
  leftIsOriginal?: boolean
}

export interface SyncControllers {
  left: EditorView
  right: EditorView
  syncNow: (source: 'left' | 'right') => void
  destroy: () => void
}

const SETTLE_MS = 150

/**
 * Scroll leader + rAF throttle + re-entrancy / settle guard.
 */
export function attachSynchronizedEditors(
  left: EditorView,
  right: EditorView,
  options: SyncOptions,
): SyncControllers {
  let pendingLeader: 'left' | 'right' | null = null
  let lockedLeader: 'left' | 'right' | null = null
  let raf = 0
  let settleTimer = 0
  let syncing = false

  const syncNow = (source: 'left' | 'right') => {
    if (syncing) return
    syncing = true
    try {
      const from = source === 'left' ? left : right
      const to = source === 'left' ? right : left
      syncViews(from, to, source, options)
    } finally {
      // Programmatic follower scroll often fires async; keep lock until settle.
      queueMicrotask(() => {
        syncing = false
      })
    }
  }

  const armSettle = (source: 'left' | 'right') => {
    lockedLeader = source
    window.clearTimeout(settleTimer)
    settleTimer = window.setTimeout(() => {
      lockedLeader = null
    }, SETTLE_MS)
  }

  const schedule = (source: 'left' | 'right') => {
    // While a pane is actively leading, ignore follower scroll echoes.
    if (lockedLeader != null && lockedLeader !== source) return
    armSettle(source)
    pendingLeader = source
    if (raf) return
    raf = requestAnimationFrame(() => {
      raf = 0
      const src = pendingLeader
      pendingLeader = null
      if (!src) return
      syncNow(src)
    })
  }

  const leftScroll = () => {
    if (syncing) return
    schedule('left')
  }
  const rightScroll = () => {
    if (syncing) return
    schedule('right')
  }

  left.scrollDOM.addEventListener('scroll', leftScroll, { passive: true })
  right.scrollDOM.addEventListener('scroll', rightScroll, { passive: true })

  return {
    left,
    right,
    syncNow: (source) => {
      armSettle(source)
      syncNow(source)
    },
    destroy: () => {
      if (raf) cancelAnimationFrame(raf)
      window.clearTimeout(settleTimer)
      left.scrollDOM.removeEventListener('scroll', leftScroll)
      right.scrollDOM.removeEventListener('scroll', rightScroll)
    },
  }
}

function syncViews(
  from: EditorView,
  to: EditorView,
  source: 'left' | 'right',
  options: SyncOptions,
) {
  const wrap = options.getWrap()
  const rect = from.scrollDOM.getBoundingClientRect()
  const gutter = 12
  const anchor = from.posAtCoords({ x: rect.left + gutter, y: rect.top + 8 })

  if (anchor == null) {
    const maxFrom = from.scrollDOM.scrollHeight - from.scrollDOM.clientHeight
    const maxTo = to.scrollDOM.scrollHeight - to.scrollDOM.clientHeight
    if (maxFrom > 0 && maxTo > 0) {
      to.scrollDOM.scrollTop = (from.scrollDOM.scrollTop / maxFrom) * maxTo
    }
    if (!wrap) to.scrollDOM.scrollLeft = from.scrollDOM.scrollLeft
    return
  }

  const line = from.state.doc.lineAt(anchor)
  const mappedLineNo = mapPhysicalLine(line.number)
  const lineTop = from.coordsAtPos(line.from)
  let offsetInLine = lineTop ? rect.top - lineTop.top : 0
  const fromLineBottom = from.coordsAtPos(line.to)
  if (fromLineBottom && lineTop) {
    const lineHeight = fromLineBottom.bottom - lineTop.top
    if (lineHeight > 0) {
      offsetInLine = Math.max(0, Math.min(offsetInLine, lineHeight - 1))
    }
  }

  const targetLine = to.state.doc.line(Math.min(mappedLineNo, to.state.doc.lines))
  const targetCoords = to.coordsAtPos(targetLine.from)
  if (!targetCoords) {
    // Off-viewport on follower: use CM scrollIntoView instead of fragile lh math.
    to.dispatch({
      effects: EditorView.scrollIntoView(targetLine.from, {
        y: 'start',
        yMargin: Math.max(0, offsetInLine),
      }),
    })
  } else {
    const toRect = to.scrollDOM.getBoundingClientRect()
    const targetBottom = to.coordsAtPos(targetLine.to)
    const targetHeight = targetBottom ? targetBottom.bottom - targetCoords.top : 0
    const clampedOffset =
      targetHeight > 0 ? Math.min(offsetInLine, Math.max(0, targetHeight - 1)) : offsetInLine
    const desiredScrollTop =
      to.scrollDOM.scrollTop + (targetCoords.top - toRect.top) - clampedOffset
    to.scrollDOM.scrollTop = Math.max(0, desiredScrollTop)
  }

  if (!wrap) {
    syncHorizontal(from, to, source, line, targetLine, options)
  }
}

/**
 * Horizontal sync: leader exposes the left-visible *logical* column; follower
 * maps through transform segments (§4.3), then aligns via coordsAtPos.
 *
 * Both panes share the original `Text`, so document offsets stay in original
 * space. Visual width on the anonymized pane comes from Decoration.replace;
 * we therefore convert logical columns with LineColumnMap, then resolve a
 * document position on the follower that corresponds to that logical column.
 */
function syncHorizontal(
  from: EditorView,
  to: EditorView,
  _source: 'left' | 'right',
  fromLine: { from: number; to: number; number: number },
  toLine: { from: number; to: number; number: number },
  options: SyncOptions,
) {
  const packed = options.getPacked()
  const plan = options.getPlan()
  const rect = from.scrollDOM.getBoundingClientRect()
  const pos = from.posAtCoords({ x: rect.left + 12, y: rect.top + 8 })
  if (pos == null) {
    to.scrollDOM.scrollLeft = from.scrollDOM.scrollLeft
    return
  }

  const fromDocCol = Math.max(0, pos - fromLine.from)
  let targetDocCol = fromDocCol

  if (packed && plan) {
    const map = buildLineColumnMap(fromLine.from, fromLine.to, packed, plan)
    // Shared Text: doc offsets are original. Map through segments so a column
    // inside a replacement snaps to the start of that span (§4.3), then align
    // via coordsAtPos (Decoration.replace already skews visual widths).
    const anonCol = map.originalToAnon(fromDocCol)
    targetDocCol = map.anonToOriginal(anonCol)
  }

  const targetPos = Math.min(toLine.to, toLine.from + targetDocCol)
  const targetCoords = to.coordsAtPos(targetPos)
  const toRect = to.scrollDOM.getBoundingClientRect()
  if (targetCoords) {
    const delta = targetCoords.left - (toRect.left + 12)
    to.scrollDOM.scrollLeft = Math.max(0, to.scrollDOM.scrollLeft + delta)
  } else {
    to.scrollDOM.scrollLeft = from.scrollDOM.scrollLeft
  }
}

/** Top visible physical line number, or -1. */
export function topVisibleLine(view: EditorView): number {
  const rect = view.scrollDOM.getBoundingClientRect()
  const pos = view.posAtCoords({ x: rect.left + 12, y: rect.top + 8 })
  if (pos == null) return -1
  return view.state.doc.lineAt(pos).number
}

/** Scroll so physical line `line` (1-based) is visible; prefers CM scrollIntoView. */
export function scrollToPhysicalLine(
  view: EditorView,
  line: number,
  offsetInLine = 0,
): void {
  const clamped = Math.max(1, Math.min(line, view.state.doc.lines))
  const target = view.state.doc.line(clamped)
  const pos = Math.min(target.from + Math.max(0, offsetInLine), target.to)
  view.dispatch({
    effects: EditorView.scrollIntoView(pos, { y: 'start', yMargin: 8 }),
  })
}
