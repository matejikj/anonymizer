import { useEffect } from 'react'
import { getCorrelationSource } from '../../correlation/correlationSessionModel.ts'
import { mountCorrelationPcapEditor } from '../../correlation/mountCorrelationPcapEditor.ts'
import { getSourceScroll } from '../../correlation/correlationReviewModel.ts'
import {
  defaultPcapSourceUi,
  getPcapSourceUi,
  rememberPcapSourceUi,
} from '../../correlation/correlationSourceUiContext.ts'
import { cs } from '../../i18n/cs.ts'
import type { PcapSourceDiscovery, PcapSourcePlan } from '../../correlation/types.ts'
import { usePcapStore } from '../../pcap/ui/pcapStore.ts'
import { getPcapSession } from '../../pcap/ui/pcapSession.ts'
import { useAppStore } from '../../app/store.ts'
import { PcapMainToolbar } from '../../pcap/ui/PcapMainToolbar.tsx'
import { PcapDataViewBar } from '../../pcap/ui/PcapDataViewBar.tsx'
import { PcapCaptureStage } from '../../pcap/ui/PcapCaptureStage.tsx'
import { PcapStatusBar } from '../../pcap/ui/PcapStatusBar.tsx'
import { PcapLiveAnnouncer } from '../../pcap/ui/PcapLiveAnnouncer.tsx'
import { PcapColoringRulesDialog } from '../../pcap/ui/PcapColoringRulesDialog.tsx'

export interface CorrelationPcapReviewProps {
  readonly sourceId: string
}

function snapshotPcapUi(sourceId: string): void {
  const s = usePcapStore.getState()
  rememberPcapSourceUi(sourceId, {
    displayFilterDraft: s.displayFilterDraft,
    displayFilterApplied: s.displayFilterApplied,
    selectedPacketIndex: s.selectedPacketIndex,
    selectedFieldPath: s.selectedFieldPath,
    selectedByteOffset: s.selectedByteOffset,
    inspectorOpen: s.inspectorOpen,
    inspectorTab: s.inspectorTab,
    detailTab: s.detailTab,
    dataView: s.dataView,
    compareLayout: s.compareLayout,
    detailBytesLayout: s.detailBytesLayout,
    filter: { ...s.filter },
  })
}

export function CorrelationPcapReview({ sourceId }: CorrelationPcapReviewProps) {
  const epoch = usePcapStore((s) => s.sessionEpoch)
  const correlationEpoch = useAppStore((s) => s.correlationEpoch)
  const planStale = usePcapStore((s) => s.planStale)

  useEffect(() => {
    const record = getCorrelationSource(sourceId)
    if (!record || record.discovery?.kind !== 'pcap' || record.plan?.kind !== 'pcap') return
    const ui = getPcapSourceUi(sourceId) ?? defaultPcapSourceUi()
    const unmount = mountCorrelationPcapEditor(
      record.discovery as PcapSourceDiscovery,
      record.plan as PcapSourcePlan,
      record.file,
      { sourceId, ui },
    )
    return () => {
      snapshotPcapUi(sourceId)
      unmount()
    }
  }, [sourceId])

  useEffect(() => {
    const record = getCorrelationSource(sourceId)
    if (!record || record.discovery?.kind !== 'pcap') return
    const packetIndex = getSourceScroll(sourceId)?.packetIndex
    const total = (record.discovery as PcapSourceDiscovery).container.descriptors.length
    if (packetIndex !== undefined && packetIndex < total) {
      usePcapStore.getState().setSelectedPacketIndex(packetIndex)
    }
  }, [sourceId, correlationEpoch])

  const record = getCorrelationSource(sourceId)
  const session = epoch >= 0 ? getPcapSession() : null

  if (!record || record.discovery?.kind !== 'pcap' || record.plan?.kind !== 'pcap') {
    return <p role="alert">{cs.correlationWorkspace.pcapUnavailable}</p>
  }

  if (!session) {
    return <p role="status">{cs.pcap.progress.analyzing}</p>
  }

  return (
    <div
      className="corr-pcap-editor pcap-workspace pcap-workspace--wireshark"
      data-testid="correlation-pcap-review"
      data-source-id={sourceId}
    >
      {planStale ? (
        <p
          className="workspace-alert workspace-alert--warn"
          role="status"
          data-testid="correlation-pcap-stale"
        >
          {cs.correlationWorkspace.rebuildBanner}
        </p>
      ) : null}
      <PcapMainToolbar fileName={session.fileName} mode="embedded" />
      <PcapDataViewBar />
      <PcapCaptureStage />
      <PcapStatusBar />
      <PcapLiveAnnouncer />
      <PcapColoringRulesDialog />
    </div>
  )
}
