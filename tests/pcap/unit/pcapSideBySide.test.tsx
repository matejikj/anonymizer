/**
 * @vitest-environment happy-dom
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'
import { clearPcapSession, resolveAnonymizedCounterpart } from '../../../src/pcap/ui/pcapSession'
import { PcapDataViewBar } from '../../../src/pcap/ui/PcapDataViewBar'
import { PcapMainToolbar } from '../../../src/pcap/ui/PcapMainToolbar'
import { PcapComparisonWorkspace } from '../../../src/pcap/ui/PcapComparisonWorkspace'
import {
  PCAP_DUAL_PANE_MIN_WIDTH,
  clampCompareRatio,
  layoutFromWorkspaceWidth,
  nextCompareLayout,
} from '../../../src/pcap/ui/pcapCompareLayout'
import { columnsForWorkspaceWidth, DEFAULT_PCAP_COLUMNS, loadPcapUiPrefs } from '../../../src/pcap/ui/pcapUiPrefs'

describe('PCAP side-by-side Original | Anonymized', () => {
  beforeEach(() => {
    clearPcapSession()
    usePcapStore.getState().resetToEmpty()
    usePcapStore.setState({
      dataView: 'anonymized',
      focusedPane: 'anonymized',
      compareLayout: 'dual',
      layoutMode: 'desktop',
      inspectorOpen: false,
      panelSizesLinked: true,
      filteredIndicesOriginal: [0, 1, 2],
      filteredIndicesAnonymized: [0, 2],
      filteredIndices: [0, 2],
      workspaceWidth: 1600,
    })
    localStorage.removeItem('rnd-log-anonymizer:pref:pcapWiresharkUi')
  })

  afterEach(() => {
    clearPcapSession()
  })

  it('uses 1100px workspace breakpoint for dual vs single', () => {
    expect(PCAP_DUAL_PANE_MIN_WIDTH).toBe(1100)
    expect(layoutFromWorkspaceWidth(1100)).toBe('dual')
    expect(layoutFromWorkspaceWidth(1099)).toBe('single')
  })

  it('uses hysteresis so dual↔single does not oscillate near the breakpoint', () => {
    expect(nextCompareLayout(1100, 'dual')).toBe('dual')
    expect(nextCompareLayout(1080, 'dual')).toBe('single')
    expect(nextCompareLayout(1100, 'single')).toBe('single')
    expect(nextCompareLayout(1120, 'single')).toBe('dual')
  })

  it('clamps compare ratio and persists prefs', () => {
    expect(clampCompareRatio(0.1)).toBe(0.35)
    expect(clampCompareRatio(0.9)).toBe(0.65)
    usePcapStore.getState().setCompareRatio(0.42)
    const loaded = loadPcapUiPrefs()
    expect(loaded.compareRatio).toBe(0.42)
  })

  it('hides Delta under full-column breakpoint', () => {
    const cols = columnsForWorkspaceWidth(
      DEFAULT_PCAP_COLUMNS.map((c) => (c.id === 'delta' ? { ...c, visible: true } : c)),
      1200,
    )
    expect(cols.find((c) => c.id === 'delta')?.visible).toBe(false)
  })

  it('dual mode hides data-view bar', () => {
    render(
      <>
        <PcapMainToolbar
          fileName="t.pcap"
          onOpenFile={() => {}}
          onExport={() => {}}
          canExport
          exportBusy={false}
          exportLabel="Export"
        />
        <PcapDataViewBar />
      </>,
    )
    expect(screen.queryByTestId('pcap-data-view-bar')).toBeNull()
    expect(screen.queryByTestId('pcap-unlink-panel-sizes')).toBeNull()
    expect(screen.queryByTestId('pcap-active-level')).toBeNull()
    expect(screen.queryByTestId('pcap-data-view-switch')).toBeNull()
  })

  it('single mode keeps Original|Anonymized switch', () => {
    usePcapStore.setState({ compareLayout: 'single' })
    render(
      <>
        <PcapMainToolbar
          fileName="t.pcap"
          onOpenFile={() => {}}
          onExport={() => {}}
          canExport
          exportBusy={false}
          exportLabel="Export"
        />
        <PcapDataViewBar />
      </>,
    )
    expect(screen.getByTestId('pcap-data-view-switch')).toBeTruthy()
    expect(screen.getByTestId('pcap-data-view-original')).toBeTruthy()
    expect(screen.queryByTestId('pcap-unlink-panel-sizes')).toBeNull()
  })

  it('resolves dropped counterpart without session', () => {
    expect(resolveAnonymizedCounterpart(-1, [])).toMatchObject({ kind: 'dropped' })
  })

  it('F6 on comparison workspace swaps focus', () => {
    render(<PcapComparisonWorkspace />)
    expect(usePcapStore.getState().focusedPane).toBe('anonymized')
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'F6' }))
    })
    expect(usePcapStore.getState().focusedPane).toBe('original')
    expect(usePcapStore.getState().liveAnnounce).toMatch(/Original/)
  })

  it('preserves selection when switching data view in single mode', () => {
    usePcapStore.setState({ compareLayout: 'single', selectedPacketIndex: 7 })
    usePcapStore.getState().setDataView('original')
    expect(usePcapStore.getState().selectedPacketIndex).toBe(7)
    expect(usePcapStore.getState().focusedPane).toBe('original')
  })

  it('renders dual workspace landmarks when session absent returns null panes safely', () => {
    // Keep dual even if ResizeObserver reports 0 in happy-dom.
    usePcapStore.setState({ compareLayout: 'dual', workspaceWidth: 1600 })
    const { container } = render(<PcapComparisonWorkspace />)
    expect(container.querySelector('[data-testid="pcap-comparison-workspace"]')).toBeTruthy()
    expect(usePcapStore.getState().compareLayout).toBe('dual')
    expect(container.querySelector('[data-testid="pcap-data-pane-original"]')).toBeTruthy()
    expect(container.querySelector('[data-testid="pcap-data-pane-anonymized"]')).toBeTruthy()
  })
})
