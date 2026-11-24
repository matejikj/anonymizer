import { PcapPanelSplitter } from './PcapPanelSplitter.tsx'
import { PcapPacketDetails } from './PcapPacketDetails.tsx'
import { PcapPacketBytes } from './PcapPacketBytes.tsx'
import { usePcapStore } from './pcapStore.ts'

export function PcapBottomPanels() {
  const detailBytesLayout = usePcapStore((s) => s.detailBytesLayout)
  const detailsPanelRatio = usePcapStore((s) => s.detailsPanelRatio)
  const setDetailsPanelRatio = usePcapStore((s) => s.setDetailsPanelRatio)

  if (detailBytesLayout === 'side-by-side') {
    return (
      <div className="pcap-bottom-panels pcap-bottom-panels--horizontal" data-testid="pcap-bottom-panels">
        <PcapPanelSplitter
          orientation="horizontal"
          ratio={detailsPanelRatio}
          onRatioChange={setDetailsPanelRatio}
          testId="pcap-details-bytes-splitter"
          primary={<PcapPacketDetails />}
          secondary={<PcapPacketBytes />}
        />
      </div>
    )
  }

  return (
    <div className="pcap-bottom-panels pcap-bottom-panels--stacked" data-testid="pcap-bottom-panels">
      <PcapPanelSplitter
        orientation="vertical"
        ratio={detailsPanelRatio}
        onRatioChange={setDetailsPanelRatio}
        testId="pcap-details-bytes-splitter"
        primary={<PcapPacketDetails />}
        secondary={<PcapPacketBytes />}
      />
    </div>
  )
}
