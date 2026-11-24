/**
 * @vitest-environment happy-dom
 */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'
import { clearPcapSession } from '../../../src/pcap/ui/pcapSession'
import { PcapDataViewBar } from '../../../src/pcap/ui/PcapDataViewBar'
import {
  DEFAULT_PCAP_COLUMNS,
  gridTemplateForColumns,
  loadPcapUiPrefs,
  resetPcapColumnPrefs,
  visibleColumns,
} from '../../../src/pcap/ui/pcapUiPrefs'

describe('PCAP Wireshark layout (step 1)', () => {
  beforeEach(() => {
    clearPcapSession()
    usePcapStore.getState().resetToEmpty()
    usePcapStore.setState({ dataView: 'anonymized', inspectorOpen: false })
    localStorage.removeItem('rnd-log-anonymizer:pref:pcapWiresharkUi')
  })

  it('defaults to anonymized data view and closed inspector', () => {
    expect(usePcapStore.getState().dataView).toBe('anonymized')
    expect(usePcapStore.getState().inspectorOpen).toBe(false)
    expect(usePcapStore.getState().layoutMode).toBe('desktop')
  })

  it('switches data view without changing selected packet', () => {
    usePcapStore.getState().setSelectedPacketIndex(7)
    usePcapStore.getState().setDataView('original')
    expect(usePcapStore.getState().selectedPacketIndex).toBe(7)
    expect(usePcapStore.getState().dataView).toBe('original')
  })

  it('renders Original warning in data view bar', () => {
    usePcapStore.setState({ compareLayout: 'single' })
    usePcapStore.getState().setDataView('original')
    render(<PcapDataViewBar />)
    expect(screen.getByTestId('pcap-original-warning')).toBeTruthy()
  })

  it('builds grid template from visible columns', () => {
    const cols = visibleColumns(DEFAULT_PCAP_COLUMNS)
    expect(cols.length).toBeGreaterThan(5)
    expect(gridTemplateForColumns(DEFAULT_PCAP_COLUMNS)).toMatch(/minmax\(/)
  })

  it('persists UI prefs to localStorage', () => {
    usePcapStore.getState().setListPanelRatio(0.5)
    usePcapStore.getState().persistUiPrefs()
    const loaded = loadPcapUiPrefs()
    expect(loaded.listPanelRatio).toBe(0.5)
  })

  it('resets columns to defaults', () => {
    usePcapStore.getState().setColumns(
      resetPcapColumnPrefs().map((c) => (c.id === 'delta' ? { ...c, visible: true } : c)),
    )
    usePcapStore.getState().resetColumns()
    expect(usePcapStore.getState().columns.find((c) => c.id === 'delta')?.visible).toBe(false)
  })

  it('data view bar keeps anonymized as default without highlight toggle', () => {
    render(<PcapDataViewBar />)
    expect(screen.queryByTestId('pcap-highlight-changes')).toBeNull()
    expect(usePcapStore.getState().dataView).toBe('anonymized')
  })
})
