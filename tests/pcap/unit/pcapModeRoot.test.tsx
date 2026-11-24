/**
 * @vitest-environment happy-dom
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { PcapModeRoot } from '../../../src/app/shell/PcapModeRoot'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'
import { clearPcapSession } from '../../../src/pcap/ui/pcapSession'
import { cs } from '../../../src/i18n/cs'

describe('PcapModeRoot UX', () => {
  beforeEach(() => {
    clearPcapSession()
    usePcapStore.getState().resetToEmpty()
  })

  it('shows empty dropzone with active level sentence (no preset cards)', () => {
    render(<PcapModeRoot />)
    expect(screen.getByTestId('pcap-mode-root')).toBeTruthy()
    expect(screen.getByTestId('pcap-empty')).toBeTruthy()
    expect(screen.getByTestId('pcap-dropzone')).toBeTruthy()
    expect(screen.getByText(/Použije se profil/)).toBeTruthy()
    // Preset cards removed — level is controlled via top-bar select only
    expect(screen.queryByRole('button', { name: /Diagnostické pro AI/ })).toBeNull()
    expect(screen.queryAllByTestId('pcap-preset-card')).toEqual([])
  })

  it('defaults to diagnostic level', () => {
    render(<PcapModeRoot />)
    expect(usePcapStore.getState().activeProfile.preset).toBe('diagnostic')
    expect(screen.getByText(/Použije se profil Diagnostické pro AI/)).toBeTruthy()
  })

  it('shows progress splash while analyzing before session exists', () => {
    usePcapStore.getState().setPhase('analyzing')
    usePcapStore.getState().setProgress({
      phase: 'analyzing',
      packetsDone: 120,
      packetsTotal: 13010,
      bytesDone: 0,
      bytesTotal: 5_000_000,
      startedAt: Date.now(),
      cancellable: true,
      fileName: 'app-crash-2.pcap',
    })

    render(<PcapModeRoot />)

    expect(screen.getByTestId('pcap-progress')).toBeTruthy()
    expect(screen.queryByTestId('pcap-workspace')).toBeNull()
    expect(screen.getByText('app-crash-2.pcap')).toBeTruthy()
    expect(screen.getByText(cs.pcap.progress.working)).toBeTruthy()
  })
})
