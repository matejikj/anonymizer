import { useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import {
  columnLabel,
  type PcapColumnId,
} from './pcapUiPrefs.ts'
import { Button, WorkspaceChrome } from '../../design-system/index.ts'
import { useAppStore } from '../../app/store.ts'
import { exportActiveMappingBundle, BundleLifecycleError } from '../../features/mapping-bundle/bundleController.ts'

export interface PcapMainToolbarProps {
  readonly fileName: string
  readonly onOpenFile?: () => void
  readonly onExport?: () => void
  readonly canExport?: boolean
  readonly exportBusy?: boolean
  readonly exportLabel?: string
  readonly isRecovery?: boolean
  readonly onExportRecovery?: () => void
  readonly exportRecoveryBusy?: boolean
  readonly onExportDiagnostics?: () => void
  readonly onDownloadDeanonymized?: () => void
  readonly onOpenRecoverySearch?: () => void
  /**
   * `embedded` = inside mixed set: keep tools/nav/columns/coloring/inspector,
   * omit open-file and set-level export actions (those live on the set chrome).
   */
  readonly mode?: 'standalone' | 'embedded'
}

/** File-level PCAP chrome — same WorkspaceChrome contract as text toolbar. */
export function PcapMainToolbar({
  fileName,
  onOpenFile,
  onExport,
  canExport = false,
  exportBusy = false,
  exportLabel = '',
  isRecovery = false,
  onExportRecovery,
  exportRecoveryBusy = false,
  onExportDiagnostics,
  onDownloadDeanonymized,
  onOpenRecoverySearch,
  mode = 'standalone',
}: PcapMainToolbarProps) {
  const embedded = mode === 'embedded'
  const filteredIndices = usePcapStore((s) => s.filteredIndices)
  const selectedPacketIndex = usePcapStore((s) => s.selectedPacketIndex)
  const setSelectedPacketIndex = usePcapStore((s) => s.setSelectedPacketIndex)
  const setInspectorOpen = usePcapStore((s) => s.setInspectorOpen)
  const resetColumns = usePcapStore((s) => s.resetColumns)
  const setDetailBytesLayout = usePcapStore((s) => s.setDetailBytesLayout)
  const detailBytesLayout = usePcapStore((s) => s.detailBytesLayout)
  const columns = usePcapStore((s) => s.columns)
  const setColumns = usePcapStore((s) => s.setColumns)
  const colorizePacketList = usePcapStore((s) => s.colorizePacketList)
  const setColorizePacketList = usePcapStore((s) => s.setColorizePacketList)
  const setColoringRulesDialogOpen = usePcapStore((s) => s.setColoringRulesDialogOpen)
  const setOutcomeDialogOpen = usePcapStore((s) => s.setOutcomeDialogOpen)
  const phase = usePcapStore((s) => s.phase)
  const [exportMappingBusy, setExportMappingBusy] = useState(false)

  const onExportMapping = async () => {
    setExportMappingBusy(true)
    try {
      await exportActiveMappingBundle({ mode: 'pcap' })
      useAppStore.getState().setToast({ message: cs.bundle.exported })
    } catch (err) {
      const message =
        err instanceof BundleLifecycleError && err.code === 'bundle-empty'
          ? cs.bundle.emptyMapping
          : cs.bundle.failed
      useAppStore.getState().setToast({ message })
    } finally {
      setExportMappingBusy(false)
    }
  }

  const pos = filteredIndices.indexOf(selectedPacketIndex)
  const goPrev = () => {
    if (pos > 0) setSelectedPacketIndex(filteredIndices[pos - 1]!)
  }
  const goNext = () => {
    if (pos >= 0 && pos < filteredIndices.length - 1) {
      setSelectedPacketIndex(filteredIndices[pos + 1]!)
    }
  }

  return (
    <WorkspaceChrome
      embedded={embedded}
      mode={mode}
      testId="pcap-main-toolbar"
      className="pcap-main-toolbar"
      context={
        <div className="workspace-chrome__meta pcap-main-toolbar__left">
          {embedded ? null : (
            <Button variant="secondary" data-testid="pcap-toolbar-open" onClick={onOpenFile}>
              {cs.pcap.workspace.toolbarOpen}
            </Button>
          )}
          <span className="workspace-chrome__file pcap-main-toolbar__file" title={fileName}>
            {fileName}
          </span>
        </div>
      }
      tools={
        <>
          <div className="workspace-chrome__nav pcap-main-toolbar__nav" aria-label={cs.pcap.workspace.toolbarNav}>
            <Button variant="ghost" data-testid="pcap-toolbar-prev" onClick={goPrev} disabled={pos <= 0}>
              {cs.pcap.workspace.toolbarPrev}
            </Button>
            <Button
              variant="ghost"
              data-testid="pcap-toolbar-next"
              onClick={goNext}
              disabled={pos < 0 || pos >= filteredIndices.length - 1}
            >
              {cs.pcap.workspace.toolbarNext}
            </Button>
          </div>
          <div className="workspace-chrome__layout pcap-main-toolbar__layout">
            <details className="pcap-main-toolbar__view">
              <summary>{cs.pcap.coloring.viewMenu}</summary>
              <div className="pcap-main-toolbar__menu">
                <label className="pcap-main-toolbar__col-toggle">
                  <input
                    type="checkbox"
                    checked={colorizePacketList}
                    onChange={(e) => setColorizePacketList(e.target.checked)}
                    data-testid="pcap-colorize-toggle"
                  />
                  {cs.pcap.coloring.colorizePacketList}
                </label>
                <Button
                  variant="ghost"
                  data-testid="pcap-coloring-rules-open"
                  onClick={() => setColoringRulesDialogOpen(true)}
                >
                  {cs.pcap.coloring.coloringRules}
                </Button>
              </div>
            </details>
            <details className="pcap-main-toolbar__columns">
              <summary>{cs.pcap.workspace.toolbarColumns}</summary>
              <div className="pcap-main-toolbar__menu">
                {columns
                  .filter((c) => c.id !== 'mark' && c.id !== 'no')
                  .map((col) => (
                    <label key={col.id} className="pcap-main-toolbar__col-toggle">
                      <input
                        type="checkbox"
                        checked={col.visible}
                        onChange={(e) =>
                          setColumns(
                            columns.map((c) =>
                              c.id === col.id ? { ...c, visible: e.target.checked } : c,
                            ),
                          )
                        }
                      />
                      {columnLabel(col.id as PcapColumnId) || col.id}
                    </label>
                  ))}
                <Button variant="ghost" onClick={() => resetColumns()}>
                  {cs.pcap.workspace.columnsReset}
                </Button>
                <Button
                  variant="ghost"
                  onClick={() =>
                    setDetailBytesLayout(detailBytesLayout === 'stacked' ? 'side-by-side' : 'stacked')
                  }
                >
                  {detailBytesLayout === 'stacked'
                    ? cs.pcap.workspace.layoutSideBySide
                    : cs.pcap.workspace.layoutStacked}
                </Button>
              </div>
            </details>
            <Button variant="ghost" data-testid="pcap-open-inspector" onClick={() => setInspectorOpen(true)}>
              {cs.pcap.inspector.open}
            </Button>
            {phase === 'workspace' && !isRecovery ? (
              <Button
                variant="ghost"
                data-testid="pcap-outcome-dialog-open"
                onClick={() => setOutcomeDialogOpen(true)}
              >
                {cs.pcap.outcome.openDialog}
              </Button>
            ) : null}
          </div>
        </>
      }
      primary={
        embedded ? undefined : (
          <div className="workspace-chrome__actions pcap-main-toolbar__right">
            {isRecovery ? (
              <>
                <Button
                  variant="ghost"
                  data-testid="pcap-recovery-search-open"
                  onClick={onOpenRecoverySearch}
                >
                  {cs.pcap.workspace.searchAnonymizedValue}
                </Button>
                <Button
                  variant="primary"
                  data-testid="pcap-download-deanonymized"
                  onClick={onDownloadDeanonymized}
                >
                  {cs.pcap.workspace.downloadDeanonymized}
                </Button>
              </>
            ) : (
              <>
                <Button
                  variant="ghost"
                  busy={exportMappingBusy}
                  data-testid="pcap-export-mapping"
                  onClick={() => void onExportMapping()}
                >
                  {cs.pcap.workspace.exportMapping}
                </Button>
                <Button
                  variant="secondary"
                  disabled={!canExport}
                  busy={exportRecoveryBusy}
                  data-testid="pcap-export-recovery"
                  onClick={onExportRecovery}
                >
                  {cs.pcap.workspace.exportRecovery}
                </Button>
                <Button
                  variant="ghost"
                  disabled={!canExport}
                  data-testid="pcap-export-diagnostics"
                  onClick={onExportDiagnostics}
                >
                  {cs.pcap.workspace.exportDiagnostics}
                </Button>
                <Button
                  variant="primary"
                  disabled={!canExport}
                  busy={exportBusy}
                  data-testid="pcap-export"
                  onClick={onExport}
                >
                  {exportBusy ? <span className="btn__spinner" aria-hidden="true" /> : null}
                  {exportLabel}
                </Button>
              </>
            )}
          </div>
        )
      }
    />
  )
}
