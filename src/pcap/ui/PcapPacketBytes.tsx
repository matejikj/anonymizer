import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { getPacketRowMeta } from './pcapSession.ts'
import { PcapByteGrid } from './PcapByteGrid.tsx'
import { usePacketDissection } from './usePacketDissection.ts'
import type { PcapDataView } from './pcapUiPrefs.ts'

export interface PcapPacketBytesProps {
  readonly dataView?: PcapDataView
}

export function PcapPacketBytes({ dataView: dataViewProp }: PcapPacketBytesProps = {}) {
  const selectedPacketIndex = usePcapStore((s) => s.selectedPacketIndex)
  const sessionEpoch = usePcapStore((s) => s.sessionEpoch)
  const storeDataView = usePcapStore((s) => s.dataView)
  const dataView = dataViewProp ?? storeDataView
  const meta = getPacketRowMeta(selectedPacketIndex)
  const { dissection, loading } = usePacketDissection(selectedPacketIndex, sessionEpoch, dataView)

  if (!meta.descriptor) {
    return (
      <section className="pcap-bytes-panel pcap-bytes-panel--empty" data-testid="pcap-packet-bytes">
        <p>{cs.pcap.detail.none}</p>
      </section>
    )
  }

  const viewLabel =
    dataView === 'original'
      ? cs.pcap.workspace.dataViewOriginal
      : cs.pcap.workspace.dataViewAnonymized

  return (
    <section
      className="pcap-bytes-panel"
      data-testid="pcap-packet-bytes"
      aria-label={cs.pcap.detail.hex}
      data-data-view={dataView}
    >
      <header className="pcap-bytes-panel__header">
        <div className="pcap-bytes-panel__title-block">
          <h3>{cs.pcap.detail.hex}</h3>
          <p className="pcap-bytes-panel__subtitle">
            {cs.pcap.detail.hexViewMeta.replace('{view}', viewLabel)}
          </p>
        </div>
      </header>
      <div className="pcap-bytes-panel__body">
        <PcapByteGrid
          sources={dissection?.sources ?? [{ id: 'frame', label: 'Frame', bytes: new Uint8Array(0), fieldMap: [] }]}
          roots={dissection?.roots ?? []}
          loading={loading}
          dataView={dataView}
        />
      </div>
    </section>
  )
}
