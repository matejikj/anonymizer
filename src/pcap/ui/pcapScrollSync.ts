/**
 * Dual packet-list scroll sync by stable packet index.
 * One rAF sync/frame, leader lock, DOM-direct follower — virtualization updates are quantized.
 */

const ROW_HEIGHT = 28
/** Keep leader lock briefly so follower echo cannot steal leadership mid-gesture. */
const SETTLE_MS = 80

export type PcapScrollPaneId = 'original' | 'anonymized'

export interface PcapListScrollPane {
  readonly getFilteredIndices: () => readonly number[]
  readonly getViewport: () => HTMLElement | null
  /**
   * Notify pane of follower scrollTop for virtualization.
   * Called after DOM scrollTop is set; may quantize React updates.
   */
  readonly setLocalScrollTop: (top: number) => void
}

const panes = new Map<PcapScrollPaneId, PcapListScrollPane>()

let leader: PcapScrollPaneId | null = null
let settleTimer = 0
let raf = 0
let applying = false
let pendingLeader: PcapScrollPaneId | null = null

export function registerPcapListScrollPane(id: PcapScrollPaneId, pane: PcapListScrollPane): () => void {
  panes.set(id, pane)
  return () => {
    panes.delete(id)
    if (leader === id) leader = null
  }
}

export function topVisiblePacketIndex(
  scrollTop: number,
  filteredIndices: readonly number[],
): number | null {
  if (filteredIndices.length === 0) return null
  const row = Math.max(0, Math.min(filteredIndices.length - 1, Math.floor(scrollTop / ROW_HEIGHT)))
  return filteredIndices[row] ?? null
}

/**
 * Scroll offset for the same packet identity, or the next/previous present row
 * when the packet was dropped/filtered on the other side (insertion-point based).
 */
export function scrollTopForRelatedPacket(
  packetIndex: number,
  filteredIndices: readonly number[],
  rowOffsetInViewport = 0,
): number | null {
  if (filteredIndices.length === 0) return null
  const exact = filteredIndices.indexOf(packetIndex)
  if (exact >= 0) return Math.max(0, exact * ROW_HEIGHT - rowOffsetInViewport)

  let lo = 0
  let hi = filteredIndices.length
  while (lo < hi) {
    const mid = (lo + hi) >> 1
    if ((filteredIndices[mid] ?? 0) < packetIndex) lo = mid + 1
    else hi = mid
  }
  const pos = lo < filteredIndices.length ? lo : Math.max(0, filteredIndices.length - 1)
  return Math.max(0, pos * ROW_HEIGHT - rowOffsetInViewport)
}

export function scrollTopForPacketIndex(
  packetIndex: number,
  filteredIndices: readonly number[],
  rowOffsetInViewport = 0,
): number | null {
  const exact = filteredIndices.indexOf(packetIndex)
  if (exact < 0) return null
  return Math.max(0, exact * ROW_HEIGHT - rowOffsetInViewport)
}

export function buildScrollAnchor(
  scrollTop: number,
  filteredIndices: readonly number[],
): { packetIndex: number; rowOffsetInViewport: number } | null {
  const packetIndex = topVisiblePacketIndex(scrollTop, filteredIndices)
  if (packetIndex === null) return null
  const pos = filteredIndices.indexOf(packetIndex)
  return { packetIndex, rowOffsetInViewport: scrollTop - pos * ROW_HEIGHT }
}

/**
 * Quantized virtual-window start used to gate React updates.
 * Steps by ~half overscan so lists stay smooth without re-rendering every row.
 */
export function virtualWindowStart(scrollTop: number, count: number, overscan = 8): number {
  const raw = Math.max(0, Math.min(count, Math.floor(scrollTop / ROW_HEIGHT) - overscan))
  const step = Math.max(1, Math.floor(overscan / 2))
  return Math.floor(raw / step) * step
}

function otherPane(id: PcapScrollPaneId): PcapScrollPaneId {
  return id === 'original' ? 'anonymized' : 'original'
}

function armSettle(id: PcapScrollPaneId): void {
  leader = id
  window.clearTimeout(settleTimer)
  settleTimer = window.setTimeout(() => {
    applying = false
    leader = null
  }, SETTLE_MS)
}

export function isPcapListScrollEcho(): boolean {
  return applying
}

/** User-driven scroll on a pane — sync the counterpart via packet anchor (≤1 work/frame). */
export function onPcapListUserScroll(id: PcapScrollPaneId, _scrollTop: number): void {
  if (applying) return
  if (leader !== null && leader !== id) return

  leader = id
  pendingLeader = id

  if (raf) return
  raf = requestAnimationFrame(() => {
    raf = 0
    const leaderId = pendingLeader
    pendingLeader = null
    if (!leaderId) return
    const source = panes.get(leaderId)
    const target = panes.get(otherPane(leaderId))
    if (!source || !target) return

    const vp = source.getViewport()
    if (!vp) return
    const top = vp.scrollTop
    const anchor = buildScrollAnchor(top, source.getFilteredIndices())
    if (!anchor) return

    const nextTop = scrollTopForRelatedPacket(
      anchor.packetIndex,
      target.getFilteredIndices(),
      anchor.rowOffsetInViewport,
    )
    if (nextTop === null) return

    const followerVp = target.getViewport()
    if (!followerVp) return
    if (Math.abs(followerVp.scrollTop - nextTop) < 0.5) {
      armSettle(leaderId)
      return
    }

    applying = true
    followerVp.scrollTop = nextTop
    target.setLocalScrollTop(nextTop)
    armSettle(leaderId)
  })
}

export { ROW_HEIGHT as PCAP_LIST_ROW_HEIGHT }
