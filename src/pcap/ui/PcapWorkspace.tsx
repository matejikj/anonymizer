import { useRef } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { getPcapSession } from './pcapSession.ts'
import { formatPacketCount } from './formatters.ts'
import { PcapMainToolbar } from './PcapMainToolbar.tsx'
import { PcapDataViewBar } from './PcapDataViewBar.tsx'
import { PcapCaptureStage } from './PcapCaptureStage.tsx'
import { PcapStatusBar } from './PcapStatusBar.tsx'
import { PcapLiveAnnouncer } from './PcapLiveAnnouncer.tsx'
import { PcapColoringRulesDialog } from './PcapColoringRulesDialog.tsx'
import { PcapRecoverySearchDialog } from './PcapRecoverySearchDialog.tsx'
import { PcapExportProgressBar } from './PcapExportProgressBar.tsx'
import { startPcapSession } from '../../app/sessionLifecycleCoordinator.ts'
import {
  startPcapExport,
  startPcapExportWithRecovery,
  startPcapExportDiagnostics,
  downloadDeanonymizedPcap,
} from './pcapExportController.ts'
import { ResolveWorkspacePanel } from '../../features/resolve-only/ResolveWorkspacePanel.tsx'
import { useAppStore } from '../../app/store.ts'
import { getPcapCoverageViewModel } from './getPcapCoverageViewModel.ts'
import { PcapOutcomeDialog } from './PcapOutcomeDialog.tsx'

function PcapInlineProgress() {
  const progress = usePcapStore((s) => s.progress)
  const label =
    progress.phase === 'building'
      ? cs.pcap.progress.building
      : progress.phase === 'coverage'
        ? cs.pcap.progress.coverage
        : cs.pcap.progress.analyzing
  return (
    <div>
      <p>{label}</p>
      {progress.packetsTotal > 0 ? (
        <p>
          {cs.pcap.progress.packets
            .replace('{done}', formatPacketCount(progress.packetsDone))
            .replace('{total}', formatPacketCount(progress.packetsTotal))}
        </p>
      ) : null}
    </div>
  )
}

export function PcapWorkspace() {
  const epoch = usePcapStore((s) => s.sessionEpoch)
  const phase = usePcapStore((s) => s.phase)
  const resolvePanelOpen = useAppStore((s) => s.resolvePanelOpen)
  const setResolvePanelOpen = useAppStore((s) => s.setResolvePanelOpen)
  const exportHint = usePcapStore((s) => s.exportHint)
  const exportBusy = usePcapStore((s) => s.exportBusy)
  const exportMessage = usePcapStore((s) => s.exportMessage)
  const setRecoverySearchDialogOpen = usePcapStore((s) => s.setRecoverySearchDialogOpen)
  const session = epoch >= 0 ? getPcapSession() : null
  const fileInputRef = useRef<HTMLInputElement>(null)

  if (!session) return null

  const vm = getPcapCoverageViewModel()
  const summary = vm?.summary
  const canExport = summary?.canExport ?? (
    session.statuses.compatibility !== 'blocked' && session.statuses.anonymization !== 'blocked'
  )

  const onExport = () => {
    if (!canExport || exportBusy) return
    void startPcapExport()
  }

  const primaryExportLabel =
    summary?.primaryAction === 'confirm-exposed'
      ? summary.primaryActionLabel
      : exportBusy
        ? cs.pcap.export.exporting
        : cs.pcap.workspace.export

  const isRecovery = session.sessionKind === 'recover'

  return (
    <section
      className="pcap-workspace pcap-workspace--wireshark"
      data-testid="pcap-workspace"
      data-reference="pcap-workspace"
      data-plan-revision={vm?.planRevision}
    >
      <PcapMainToolbar
        fileName={session.fileName}
        onOpenFile={() => fileInputRef.current?.click()}
        onExport={onExport}
        canExport={canExport}
        exportBusy={exportBusy}
        exportLabel={primaryExportLabel}
        isRecovery={isRecovery}
        onExportRecovery={() => {
          if (!canExport || exportBusy) return
          void startPcapExportWithRecovery()
        }}
        exportRecoveryBusy={exportBusy}
        onExportDiagnostics={() => startPcapExportDiagnostics()}
        onDownloadDeanonymized={() => downloadDeanonymizedPcap()}
        onOpenRecoverySearch={() => setRecoverySearchDialogOpen(true)}
      />

      <PcapDataViewBar />

      {resolvePanelOpen ? (
        <ResolveWorkspacePanel source="active-session" onClose={() => setResolvePanelOpen(false)} />
      ) : null}

      {!canExport && !exportMessage ? (
        <p
          id="pcap-export-blocked-hint"
          className="pcap-workspace__hint pcap-workspace__hint--blocked"
          role="status"
          data-testid="pcap-export-blocked-hint"
        >
          {cs.pcap.export.blockedHint}
        </p>
      ) : null}
      {exportMessage ? (
        <>
          <p
            className={`pcap-workspace__hint${exportBusy ? '' : ' pcap-workspace__hint--status'}`}
            role="status"
            data-testid="pcap-export-hint"
          >
            {exportMessage}
          </p>
          {exportBusy ? <PcapExportProgressBar /> : null}
        </>
      ) : exportHint ? (
        <p className="pcap-workspace__hint" role="status" data-testid="pcap-export-hint">
          {exportHint}
        </p>
      ) : null}

      <PcapCaptureStage
        loading={phase === 'analyzing'}
        loadingContent={<PcapInlineProgress />}
      />

      <PcapLiveAnnouncer />
      <PcapOutcomeDialog />
      <PcapColoringRulesDialog />
      <PcapRecoverySearchDialog />
      <PcapStatusBar />

      <input
        ref={fileInputRef}
        type="file"
        accept=".pcap,.pcapng,application/octet-stream"
        className="visually-hidden"
        tabIndex={-1}
        aria-label={cs.pcap.empty.chooseFile}
        data-testid="pcap-workspace-file-input"
        onChange={(e) => {
          const f = e.target.files?.[0]
          if (f) void startPcapSession(f)
        }}
      />
    </section>
  )
}
