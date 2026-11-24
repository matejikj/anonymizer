/**
 * Isolated Wireshark-like Original or Anonymized data pane (list → details → bytes).
 */

import { useMemo } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { getPcapSession, resolveAnonymizedCounterpart, type PacketCounterpartState } from './pcapSession.ts'
import { PcapPacketTables } from './PcapPacketTables.tsx'
import { PcapPacketDetails } from './PcapPacketDetails.tsx'
import { PcapPacketBytes } from './PcapPacketBytes.tsx'
import { PcapPanelSplitter } from './PcapPanelSplitter.tsx'
import { formatPacketCount } from './formatters.ts'
import type { PcapDataView } from './pcapUiPrefs.ts'

export interface PcapDataPaneProps {
  readonly dataView: PcapDataView
  readonly focused: boolean
  readonly onFocusPane: () => void
}

export function PcapDataPane({ dataView, focused, onFocusPane }: PcapDataPaneProps) {
  const filteredIndicesOriginal = usePcapStore((s) => s.filteredIndicesOriginal)
  const filteredIndicesAnonymized = usePcapStore((s) => s.filteredIndicesAnonymized)
  const selectedPacketIndex = usePcapStore((s) => s.selectedPacketIndex)
  const listPanelRatio = usePcapStore((s) => s.listPanelRatio)
  const setListPanelRatio = usePcapStore((s) => s.setListPanelRatio)
  const detailsPanelRatio = usePcapStore((s) => s.detailsPanelRatio)
  const setDetailsPanelRatio = usePcapStore((s) => s.setDetailsPanelRatio)
  const detailBytesLayout = usePcapStore((s) => s.detailBytesLayout)
  const scrollTopOriginal = usePcapStore((s) => s.scrollTopOriginal)
  const scrollTopAnonymized = usePcapStore((s) => s.scrollTopAnonymized)
  const setPaneScrollTop = usePcapStore((s) => s.setPaneScrollTop)
  const revealFilteredCounterpart = usePcapStore((s) => s.revealFilteredCounterpart)
  const setRevealFilteredCounterpart = usePcapStore((s) => s.setRevealFilteredCounterpart)
  const sessionEpoch = usePcapStore((s) => s.sessionEpoch)
  const isRecovery = sessionEpoch >= 0 && getPcapSession()?.sessionKind === 'recover'

  const filteredIndices = dataView === 'original' ? filteredIndicesOriginal : filteredIndicesAnonymized
  const scrollTop = dataView === 'original' ? scrollTopOriginal : scrollTopAnonymized

  const counterpart: PacketCounterpartState | null = useMemo(() => {
    if (dataView !== 'anonymized' || selectedPacketIndex < 0 || isRecovery) return null
    return resolveAnonymizedCounterpart(selectedPacketIndex, filteredIndicesAnonymized)
  }, [dataView, selectedPacketIndex, filteredIndicesAnonymized, isRecovery])

  const showDropped = counterpart?.kind === 'dropped'
  const showFiltered =
    counterpart?.kind === 'filtered' && !revealFilteredCounterpart && !filteredIndices.includes(selectedPacketIndex)

  const title = isRecovery
    ? dataView === 'original'
      ? cs.pcap.workspace.paneAnonymizedRecoveryTitle
      : cs.pcap.workspace.paneDeanonymizedTitle
    : dataView === 'original'
      ? cs.pcap.workspace.paneOriginalTitle
      : cs.pcap.workspace.paneAnonymizedTitle
  const badge = isRecovery
    ? dataView === 'original'
      ? cs.pcap.workspace.paneAnonymizedRecoveryBadge
      : cs.pcap.workspace.paneDeanonymizedBadge
    : dataView === 'original'
      ? cs.pcap.workspace.paneOriginalBadge
      : cs.pcap.workspace.paneAnonymizedBadge

  const bottom =
    showDropped || showFiltered ? (
      <CounterpartEmptyState
        state={counterpart!}
        onReveal={() => setRevealFilteredCounterpart(true)}
      />
    ) : detailBytesLayout === 'side-by-side' ? (
      <div className="pcap-bottom-panels pcap-bottom-panels--horizontal" data-testid={`pcap-bottom-panels-${dataView}`}>
        <PcapPanelSplitter
          orientation="horizontal"
          ratio={detailsPanelRatio}
          onRatioChange={setDetailsPanelRatio}
          testId={`pcap-details-bytes-splitter-${dataView}`}
          primary={<PcapPacketDetails dataView={dataView} />}
          secondary={<PcapPacketBytes dataView={dataView} />}
        />
      </div>
    ) : (
      <div className="pcap-bottom-panels pcap-bottom-panels--stacked" data-testid={`pcap-bottom-panels-${dataView}`}>
        <PcapPanelSplitter
          orientation="vertical"
          ratio={detailsPanelRatio}
          onRatioChange={setDetailsPanelRatio}
          testId={`pcap-details-bytes-splitter-${dataView}`}
          primary={<PcapPacketDetails dataView={dataView} />}
          secondary={<PcapPacketBytes dataView={dataView} />}
        />
      </div>
    )

  return (
    <section
      className={`pcap-data-pane pcap-data-pane--${dataView}${focused ? ' pcap-data-pane--focused' : ''}`}
      data-testid={`pcap-data-pane-${dataView}`}
      data-data-view={dataView}
      data-focused={focused ? 'true' : undefined}
      aria-label={title}
      onFocusCapture={onFocusPane}
      onMouseDown={onFocusPane}
    >
      <header className="pcap-data-pane__header">
        <span className="pcap-data-pane__title">{title}</span>
        <span className={`pcap-data-pane__badge pcap-data-pane__badge--${dataView}`}>{badge}</span>
        <span className="pcap-data-pane__count" data-testid={`pcap-pane-displayed-${dataView}`}>
          {cs.pcap.workspace.paneDisplayed.replace('{n}', formatPacketCount(filteredIndices.length))}
        </span>
      </header>
      <PcapPanelSplitter
        orientation="vertical"
        ratio={listPanelRatio}
        onRatioChange={setListPanelRatio}
        testId={`pcap-list-detail-splitter-${dataView}`}
        primary={
          <div className="pcap-data-pane__section pcap-data-pane__section--list">
            <PcapPacketTables
              dataView={dataView}
              filteredIndices={filteredIndices}
              scrollTop={scrollTop}
              onScrollTop={(top) => setPaneScrollTop(dataView, top)}
              testId={`pcap-packet-grid-${dataView}`}
            />
          </div>
        }
        secondary={<div className="pcap-data-pane__section pcap-data-pane__section--bottom">{bottom}</div>}
      />
    </section>
  )
}

function CounterpartEmptyState({
  state,
  onReveal,
}: {
  state: PacketCounterpartState
  onReveal: () => void
}) {
  if (state.kind === 'dropped') {
    return (
      <div className="pcap-counterpart-empty" data-testid="pcap-counterpart-dropped" role="status">
        <p>{cs.pcap.workspace.counterpartDropped}</p>
        <p className="pcap-counterpart-empty__meta">
          {cs.pcap.workspace.counterpartDroppedReason
            .replace('{n}', String(state.originalPacketNumber))
            .replace('{reason}', state.reason)}
        </p>
      </div>
    )
  }
  if (state.kind === 'filtered') {
    return (
      <div className="pcap-counterpart-empty" data-testid="pcap-counterpart-filtered" role="status">
        <p>{cs.pcap.workspace.counterpartFiltered}</p>
        <button type="button" data-testid="pcap-counterpart-reveal" onClick={onReveal}>
          {cs.pcap.workspace.counterpartReveal}
        </button>
      </div>
    )
  }
  return null
}
