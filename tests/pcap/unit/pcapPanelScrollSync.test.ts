/** @vitest-environment happy-dom */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPcapPanelScrollSync } from '../../../src/pcap/ui/pcapPanelScrollSync'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'

let callbacks: Map<number, FrameRequestCallback>
beforeEach(() => {
  callbacks = new Map()
  let next = 0
  vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => { callbacks.set(++next, cb); return next })
  vi.stubGlobal('cancelAnimationFrame', (id: number) => callbacks.delete(id))
})
afterEach(() => vi.unstubAllGlobals())
function flush() {
  const work = [...callbacks.values()]
  callbacks.clear()
  for (const cb of work) cb(0)
}
function pane(view: 'original' | 'anonymized', maxTop = 1000, scope = 'packet-1') {
  const element = document.createElement('div')
  Object.defineProperties(element, {
    clientHeight: { value: 200 }, scrollHeight: { value: maxTop + 200 },
    clientWidth: { value: 100 }, scrollWidth: { value: 500 },
  })
  return { view, scope, element, notify: vi.fn() }
}

describe('paired packet panel scroll', () => {
  it('resets the shared detail tab only when selecting another packet, including history', () => {
    const store = usePcapStore.getState()
    store.resetToEmpty()
    store.setSelectedPacketIndex(0)
    store.setDetailTab('changes')
    store.setSelectedPacketIndex(0)
    expect(usePcapStore.getState().detailTab).toBe('changes')
    store.pushSelectionSnapshot({ packetIndex: 0, fieldPath: null, byteOffset: 0 })
    store.pushSelectionSnapshot({ packetIndex: 0, fieldPath: null, byteOffset: 1 })
    store.pushSelectionSnapshot({ packetIndex: 1, fieldPath: null, byteOffset: 0 })
    store.navigateSelectionHistory(-1)
    expect(usePcapStore.getState().detailTab).toBe('changes')
    store.navigateSelectionHistory(1)
    expect(usePcapStore.getState().detailTab).toBe('tree')
    store.setDetailTab('changes')
    store.setSelectedPacketIndex(2)
    expect(usePcapStore.getState().detailTab).toBe('tree')
  })
  it('coalesces scrolling and immediately accepts a gesture on the opposite pane', () => {
    const sync = createPcapPanelScrollSync()
    const left = pane('original'), right = pane('anonymized')
    sync.register('bytes:frame', left); sync.register('bytes:frame', right)
    for (const top of [100, 300, 600]) {
      left.element.scrollTop = top
      left.element.scrollLeft = 50
      sync.scroll('bytes:frame', left)
    }
    expect(callbacks.size).toBe(1)
    flush()
    expect(right.element.scrollTop).toBe(600)
    expect(right.element.scrollLeft).toBe(50)
    expect(right.notify).toHaveBeenLastCalledWith(600)
    // Native follower echo doesn't schedule a return trip.
    sync.scroll('bytes:frame', right)
    expect(callbacks.size).toBe(0)
    right.element.scrollTop = 150
    sync.scroll('bytes:frame', right)
    flush()
    expect(left.element.scrollTop).toBe(150)
    sync.dispose()
  })

  it('clamps a truncated counterpart without pulling the longer source back', () => {
    const sync = createPcapPanelScrollSync()
    const left = pane('original'), right = pane('anonymized', 100)
    sync.register('bytes:frame', left); sync.register('bytes:frame', right)
    left.element.scrollTop = 800
    sync.scroll('bytes:frame', left); flush()
    expect(right.element.scrollTop).toBe(100)
    sync.scroll('bytes:frame', right); flush()
    expect(left.element.scrollTop).toBe(800)
    sync.dispose()
  })

  it('catches up a counterpart that mounts after asynchronous hydration', () => {
    const sync = createPcapPanelScrollSync()
    const left = pane('original'), right = pane('anonymized')
    sync.register('bytes:frame', left)
    left.element.scrollTop = 500
    sync.scroll('bytes:frame', left); flush()
    sync.register('bytes:frame', right)
    expect(right.element.scrollTop).toBe(500)
    expect(right.notify).toHaveBeenCalledWith(500)
    sync.dispose()
  })

  it('isolates bytes, tree, changes, byte sources and packet identities', () => {
    const sync = createPcapPanelScrollSync()
    const left = pane('original'), right = pane('anonymized')
    const otherSource = pane('anonymized'), otherPacket = pane('anonymized', 1000, 'packet-2')
    const tree = pane('anonymized'), changes = pane('anonymized')
    sync.register('bytes:frame', left); sync.register('bytes:frame', otherPacket)
    sync.register('bytes:decoded', otherSource)
    sync.register('tree', tree); sync.register('changes', changes)
    left.element.scrollTop = 300
    sync.scroll('bytes:frame', left); flush()
    for (const target of [otherSource, otherPacket, tree, changes]) expect(target.element.scrollTop).toBe(0)
    sync.register('bytes:frame', right)
    expect(right.element.scrollTop).toBe(300)
    sync.dispose()
  })

  it('cancels queued work and discards old positions when packets or workspaces unmount', () => {
    const sync = createPcapPanelScrollSync()
    const left = pane('original'), right = pane('anonymized')
    const unregisterLeft = sync.register('tree', left)
    const unregisterRight = sync.register('tree', right)
    left.element.scrollTop = 400
    sync.scroll('tree', left)
    unregisterLeft(); unregisterRight()
    const next = pane('anonymized', 100, 'packet-2')
    sync.register('tree', next); flush()
    expect(next.element.scrollTop).toBe(0)
    expect(right.element.scrollTop).toBe(0)
    next.element.scrollTop = 50
    sync.scroll('tree', next)
    sync.dispose()
    expect(callbacks.size).toBe(0)
  })
})
