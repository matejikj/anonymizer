/** @vitest-environment happy-dom */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render } from '@testing-library/react'
import { PcapByteGrid } from '../../../src/pcap/ui/PcapByteGrid'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'

const sources = [{ id: 'frame', label: 'Frame', bytes: new Uint8Array(16_000), fieldMap: [] }]

beforeEach(() => usePcapStore.getState().resetToEmpty())
afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('byte viewport lifecycle', () => {
  it('measures and observes the new viewport after loading and loading another packet', () => {
    let height = 300
    const observers: { callback: ResizeObserverCallback; observe: ReturnType<typeof vi.fn>; disconnect: ReturnType<typeof vi.fn> }[] = []
    vi.stubGlobal('ResizeObserver', class {
      observe = vi.fn()
      disconnect = vi.fn()
      constructor(callback: ResizeObserverCallback) { observers.push({ callback, observe: this.observe, disconnect: this.disconnect }) }
    })
    vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockImplementation(() => height)
    const { container, rerender } = render(<PcapByteGrid sources={sources} roots={[]} loading />)
    rerender(<PcapByteGrid sources={sources} roots={[]} />)
    const grid = container.querySelector('.pcap-byte-grid')!
    expect(observers).toHaveLength(1)
    expect(observers[0]!.observe).toHaveBeenCalledWith(grid)
    expect(container.querySelectorAll('.pcap-byte-grid__row')).toHaveLength(35)
    grid.scrollTop = 1000
    fireEvent.scroll(grid)
    expect(container.querySelector('[data-byte-offset="1104"]')).toBeTruthy()
    act(() => observers[0]!.callback([{ contentRect: { height: 700 } } as ResizeObserverEntry], {} as ResizeObserver))
    expect(container.querySelectorAll('.pcap-byte-grid__row')).toHaveLength(55)
    rerender(<PcapByteGrid sources={sources} roots={[]} loading />)
    expect(observers[0]!.disconnect).toHaveBeenCalledOnce()
    height = 500
    rerender(<PcapByteGrid sources={sources} roots={[]} />)
    expect(observers).toHaveLength(2)
    expect(observers[1]!.observe).toHaveBeenCalledWith(container.querySelector('.pcap-byte-grid'))
    expect(container.querySelectorAll('.pcap-byte-grid__row')).toHaveLength(45)
    expect(container.querySelector('.pcap-byte-grid__byte')?.getAttribute('data-byte-offset')).toBe('0')
  })

  it('measures the new viewport after loading when ResizeObserver is unavailable', () => {
    vi.stubGlobal('ResizeObserver', undefined)
    vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(500)
    const { container, rerender } = render(<PcapByteGrid sources={sources} roots={[]} loading />)
    rerender(<PcapByteGrid sources={sources} roots={[]} />)
    expect(container.querySelectorAll('.pcap-byte-grid__row')).toHaveLength(45)
  })
})
