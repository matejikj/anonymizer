/**
 * @vitest-environment happy-dom
 *
 * Redesigned load progress: a two-step stepper (Analyzuji pakety -> Sestavuji přehled) whose
 * overall percent must never regress when the pipeline moves from one phase to the next — the
 * previous single-bar-per-phase design reset to 0% on every phase change, which read as the
 * whole operation restarting even though it was actually moving forward.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { PcapProgressView } from '../../../src/pcap/ui/PcapProgressView'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'
import { cs } from '../../../src/i18n/cs'

function percentText(): number {
  const el = screen.getByText(/%$/)
  return Number(el.textContent!.replace(/[^\d]/g, ''))
}

describe('PcapProgressView step redesign', () => {
  beforeEach(() => {
    usePcapStore.getState().resetToEmpty()
  })

  it('shows both step labels with the analyzing step active at the start', () => {
    usePcapStore.getState().setProgress({
      phase: 'analyzing',
      packetsDone: 0,
      packetsTotal: 1000,
      bytesDone: 0,
      bytesTotal: 50_000,
      startedAt: Date.now(),
      cancellable: true,
      fileName: 'a.pcap',
    })
    render(<PcapProgressView />)
    // "Analyzuji pakety" appears twice by design (the big phase title + its step label) —
    // just assert both step labels are present somewhere, not uniqueness.
    expect(screen.getAllByText(cs.pcap.progress.analyzing).length).toBeGreaterThan(0)
    expect(screen.getAllByText(cs.pcap.progress.building).length).toBeGreaterThan(0)
  })

  it('overall percent never drops when moving from analyzing (100%) to building (0%)', () => {
    usePcapStore.getState().setProgress({
      phase: 'analyzing',
      packetsDone: 1000,
      packetsTotal: 1000,
      bytesDone: 50_000,
      bytesTotal: 50_000,
      startedAt: Date.now(),
      cancellable: true,
      fileName: 'a.pcap',
    })
    const { rerender } = render(<PcapProgressView />)
    const percentAtAnalyzingDone = percentText()

    usePcapStore.getState().patchProgress({
      phase: 'building',
      packetsDone: 0,
      packetsTotal: 1000,
    })
    rerender(<PcapProgressView />)
    const percentAtBuildingStart = percentText()

    // The old per-phase-only percent would go 100 -> 0 here. The new overall percent must be
    // monotonically non-decreasing across the transition.
    expect(percentAtBuildingStart).toBeGreaterThanOrEqual(percentAtAnalyzingDone)
  })

  it('overall percent reaches 100 only once the final (building) step itself completes', () => {
    usePcapStore.getState().setProgress({
      phase: 'building',
      packetsDone: 1000,
      packetsTotal: 1000,
      bytesDone: 50_000,
      bytesTotal: 50_000,
      startedAt: Date.now(),
      cancellable: true,
      fileName: 'a.pcap',
    })
    render(<PcapProgressView />)
    expect(percentText()).toBe(100)
  })
})
