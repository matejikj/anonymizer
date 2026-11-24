import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'

/** Original | Anonymized switch (single layout) + original-data warning. */
export function PcapDataViewBar() {
  const dataView = usePcapStore((s) => s.dataView)
  const setDataView = usePcapStore((s) => s.setDataView)
  const compareLayout = usePcapStore((s) => s.compareLayout)
  const dual = compareLayout === 'dual'

  if (dual) return null

  return (
    <div className="pcap-data-view-bar" data-testid="pcap-data-view-bar" data-mode="single">
      <div
        className="pcap-data-view-bar__switch"
        role="group"
        aria-label={cs.pcap.workspace.dataViewLabel}
        data-testid="pcap-data-view-switch"
      >
        <button
          type="button"
          className={dataView === 'anonymized' ? 'is-active' : ''}
          aria-pressed={dataView === 'anonymized'}
          data-testid="pcap-data-view-anonymized"
          onClick={() => setDataView('anonymized')}
        >
          {cs.pcap.workspace.dataViewAnonymized}
        </button>
        <button
          type="button"
          className={`pcap-data-view-bar__original${dataView === 'original' ? ' is-active' : ''}`}
          aria-pressed={dataView === 'original'}
          data-testid="pcap-data-view-original"
          onClick={() => setDataView('original')}
        >
          {cs.pcap.workspace.dataViewOriginal}
        </button>
      </div>
      {dataView === 'original' ? (
        <p className="pcap-data-view-bar__warn" role="status" data-testid="pcap-original-warning">
          {cs.pcap.workspace.originalDataWarning}
        </p>
      ) : null}
    </div>
  )
}
