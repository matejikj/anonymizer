import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from 'react'
import type { PcapDataView } from './pcapUiPrefs'
import { usePcapStore } from './pcapStore'

interface Position { top: number; left: number }
interface Pane {
  view: PcapDataView
  scope: string
  element: HTMLElement
  notify: (top: number) => void
  expected?: Position
}
interface Group {
  panes: Map<PcapDataView, Pane>
  position?: Position & { scope: string }
  pending?: { pane: Pane; position: Position }
}

/** One coordinator per workspace. Scroll state stays out of the packet/session store. */
export function createPcapPanelScrollSync() {
  const groups = new Map<string, Group>()
  let frame = 0

  function apply(pane: Pane, position: Position) {
    const el = pane.element
    const top = Math.max(0, Math.min(position.top, el.scrollHeight - el.clientHeight))
    const left = Math.max(0, Math.min(position.left, el.scrollWidth - el.clientWidth))
    if (Math.abs(el.scrollTop - top) < 0.5 && Math.abs(el.scrollLeft - left) < 0.5) return
    el.scrollTop = top
    el.scrollLeft = left
    // Remember the actual clamped position: the follower's native event must not echo back.
    pane.expected = { top: el.scrollTop, left: el.scrollLeft }
    pane.notify(el.scrollTop)
  }

  return {
    register(channel: string, pane: Pane) {
      let group = groups.get(channel)
      if (!group) { group = { panes: new Map() }; groups.set(channel, group) }
      group.panes.set(pane.view, pane)
      if (group.position?.scope === pane.scope) apply(pane, group.position)
      return () => {
        if (group.panes.get(pane.view) !== pane) return
        group.panes.delete(pane.view)
        if (group.pending?.pane === pane) group.pending = undefined
        if (group.panes.size === 0) groups.delete(channel)
      }
    },
    scroll(channel: string, pane: Pane) {
      const group = groups.get(channel)
      if (group?.panes.get(pane.view) !== pane) return
      const position = { top: pane.element.scrollTop, left: pane.element.scrollLeft }
      const expected = pane.expected
      pane.expected = undefined
      if (expected && Math.abs(expected.top - position.top) < 0.5 && Math.abs(expected.left - position.left) < 0.5) return
      group.position = { ...position, scope: pane.scope }
      group.pending = { pane, position }
      if (frame) return
      frame = requestAnimationFrame(() => {
        frame = 0
        for (const current of groups.values()) {
          const pending = current.pending
          current.pending = undefined
          if (!pending) continue
          for (const target of current.panes.values()) {
            if (target !== pending.pane && target.scope === pending.pane.scope) apply(target, pending.position)
          }
        }
      })
    },
    dispose() {
      if (frame) cancelAnimationFrame(frame)
      frame = 0
      groups.clear()
    },
  }
}

const ScrollSyncContext = createContext<ReturnType<typeof createPcapPanelScrollSync> | null>(null)

export function PcapPanelScrollSyncProvider({ children }: { children: ReactNode }) {
  const [sync] = useState(createPcapPanelScrollSync)
  useEffect(() => () => sync.dispose(), [sync])
  return <ScrollSyncContext.Provider value={sync}>{children}</ScrollSyncContext.Provider>
}

/** Also registers replacement DOM viewports after asynchronous packet hydration. */
export function usePcapPanelScrollSync({ channel, dataView, viewport, enabled = true, onLocalScroll }: {
  channel: string
  dataView: PcapDataView
  viewport: RefObject<HTMLElement | null>
  enabled?: boolean
  onLocalScroll?: (top: number) => void
}) {
  const sync = useContext(ScrollSyncContext)
  const scope = usePcapStore(s => `${s.sessionEpoch}:${s.selectedPacketIndex}`)
  const pane = useRef<Pane | null>(null)
  const notify = useRef(onLocalScroll)
  notify.current = onLocalScroll

  useLayoutEffect(() => {
    const element = viewport.current
    if (!enabled || !element) return
    element.scrollTop = 0
    element.scrollLeft = 0
    notify.current?.(0)
    const entry: Pane = { view: dataView, scope, element, notify: top => notify.current?.(top) }
    pane.current = entry
    const unregister = sync?.register(channel, entry)
    return () => { unregister?.(); pane.current = null }
  }, [sync, channel, dataView, scope, viewport, enabled])

  return useCallback(() => {
    const entry = pane.current
    if (!entry) return
    notify.current?.(entry.element.scrollTop)
    sync?.scroll(channel, entry)
  }, [sync, channel])
}
