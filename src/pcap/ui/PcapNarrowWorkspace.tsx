import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { PcapPacketTables } from './PcapPacketTables.tsx'
import { PcapPacketDetails } from './PcapPacketDetails.tsx'
import { PcapPacketBytes } from './PcapPacketBytes.tsx'

export function PcapNarrowWorkspace() {
  const narrowPanel = usePcapStore((s) => s.narrowPanel)
  const setNarrowPanel = usePcapStore((s) => s.setNarrowPanel)
  const dataView = usePcapStore((s) => s.dataView)
  const filteredIndicesOriginal = usePcapStore((s) => s.filteredIndicesOriginal)
  const filteredIndicesAnonymized = usePcapStore((s) => s.filteredIndicesAnonymized)
  const scrollTopOriginal = usePcapStore((s) => s.scrollTopOriginal)
  const scrollTopAnonymized = usePcapStore((s) => s.scrollTopAnonymized)
  const setPaneScrollTop = usePcapStore((s) => s.setPaneScrollTop)

  const filteredIndices = dataView === 'original' ? filteredIndicesOriginal : filteredIndicesAnonymized
  const scrollTop = dataView === 'original' ? scrollTopOriginal : scrollTopAnonymized

  return (
    <div className="pcap-narrow-workspace" data-testid="pcap-narrow-workspace">
      <div className="pcap-narrow-workspace__tabs" role="tablist" aria-label={cs.pcap.workspace.narrowTabs}>
        {(['list', 'details', 'bytes'] as const).map((panel) => (
          <button
            key={panel}
            type="button"
            role="tab"
            aria-selected={narrowPanel === panel}
            className={narrowPanel === panel ? 'is-active' : ''}
            data-testid={`pcap-narrow-tab-${panel}`}
            onClick={() => setNarrowPanel(panel)}
          >
            {cs.pcap.workspace.narrowTab[panel]}
          </button>
        ))}
      </div>
      <div className="pcap-narrow-workspace__panel" role="tabpanel">
        {narrowPanel === 'list' ? (
          <PcapPacketTables
            dataView={dataView}
            filteredIndices={filteredIndices}
            scrollTop={scrollTop}
            onScrollTop={(top) => setPaneScrollTop(dataView, top)}
            testId={`pcap-packet-grid-${dataView}`}
          />
        ) : narrowPanel === 'details' ? (
          <PcapPacketDetails dataView={dataView} />
        ) : (
          <PcapPacketBytes dataView={dataView} />
        )}
      </div>
    </div>
  )
}
