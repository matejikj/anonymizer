/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AppShell } from '../../src/features/workspace/AppShell.tsx'
import { useAppStore } from '../../src/app/store.ts'
import { usePcapStore } from '../../src/pcap/ui/pcapStore.ts'

describe('sample log / text workspace routing', () => {
  beforeEach(() => {
    useAppStore.getState().resetSession()
    useAppStore.getState().setActiveMode('pcap')
    usePcapStore.getState().resetToEmpty()
  })

  it('renders text workspace when phase is workspace even if activeMode was pcap', () => {
    useAppStore.getState().setPhase('workspace')
    useAppStore.getState().bumpSessionEpoch()

    render(<AppShell />)

    expect(screen.getByTestId('workspace')).toBeInTheDocument()
  })
})
