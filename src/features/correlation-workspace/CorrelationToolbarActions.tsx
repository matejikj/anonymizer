import { useRef, useState } from 'react'
import { useAppStore } from '../../app/store.ts'
import { cs } from '../../i18n/cs.ts'
import { Button } from '../../design-system/index.ts'
import {
  BundleCancelledError,
  BundleLifecycleError,
  cancelBundleJob,
  canExportCorrelationMappingBundle,
  exportCorrelationMappingBundle,
} from '../mapping-bundle/bundleController.ts'
import { MappingBundleExportDialog } from '../mapping-bundle/MappingBundleDialogs.tsx'
import { leaveCorrelationReview } from '../../correlation/correlationWorkspaceController.ts'

function bundleErrorMessage(err: unknown): string {
  if (err instanceof BundleLifecycleError) {
    if (err.code === 'bundle-empty') return cs.bundle.emptyMapping
    return err.message
  }
  if (err instanceof Error) return err.message
  return cs.bundle.failed
}

/**
 * Global set chrome: close · export map · export files.
 * Lives in the single set row (DESIGN_MOVES step 3); primary export stays visible when disabled.
 */
export function CorrelationToolbarActions(props: {
  readonly addBusy: boolean
  readonly exportBusy: boolean
  readonly readyCount: number
  readonly unstable?: boolean
  readonly onExportOpen: () => void
}) {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const abortRef = useRef<AbortController | null>(null)

  const planBusy = useAppStore((s) => s.planBusy)
  const unstable = Boolean(props.unstable) || planBusy
  const mappingDisabled =
    !canExportCorrelationMappingBundle() || props.exportBusy || props.addBusy || busy || unstable
  const sessionBusy = props.exportBusy || props.addBusy || busy || unstable
  const exportDisabled = props.readyCount === 0 || sessionBusy
  const exportBlockedHint = unstable
    ? cs.correlationExport.unstableSet
    : props.readyCount === 0
      ? cs.correlationWorkspace.exportBlockedNoReady
      : undefined

  const closeDialog = () => {
    if (busy) {
      abortRef.current?.abort()
      cancelBundleJob()
    }
    setDialogOpen(false)
    setBusy(false)
  }

  const runExport = async () => {
    abortRef.current?.abort()
    const ac = new AbortController()
    abortRef.current = ac
    setBusy(true)
    try {
      await exportCorrelationMappingBundle({ signal: ac.signal })
      useAppStore.getState().setToast({ message: cs.bundle.exported })
      setDialogOpen(false)
    } catch (err) {
      if (err instanceof BundleCancelledError) {
        useAppStore.getState().setToast({ message: cs.bundle.cancelled })
        return
      }
      useAppStore.getState().setToast({ message: bundleErrorMessage(err) })
    } finally {
      setBusy(false)
      abortRef.current = null
    }
  }

  return (
    <div className="corr-workspace__toolbar-actions" data-testid="correlation-toolbar-actions">
      <Button
        variant="secondary"
        data-testid="correlation-close-session"
        disabled={sessionBusy}
        title={cs.correlationWorkspace.closeHint}
        aria-description={cs.correlationWorkspace.closeHint}
        onClick={() => leaveCorrelationReview()}
      >
        {cs.correlationWorkspace.close}
      </Button>

      <div className="corr-workspace__action-divider" aria-hidden="true" />

      <div className="corr-workspace__action-group corr-workspace__action-group--end">
        <Button
          variant="ghost"
          data-testid="correlation-workspace-bundle-export"
          disabled={mappingDisabled}
          title={`${cs.bundle.mapMenuHint} ${cs.correlationCompletion.privateFormatNote}`}
          onClick={() => setDialogOpen(true)}
        >
          {cs.bundle.exportToolbar}
        </Button>
        <Button
          variant="primary"
          data-testid="correlation-export-open"
          disabled={exportDisabled}
          aria-describedby={exportBlockedHint ? 'corr-export-blocked-hint' : undefined}
          title={exportBlockedHint}
          onClick={props.onExportOpen}
        >
          {cs.correlationWorkspace.exportFiles}
        </Button>
      </div>

      {exportBlockedHint ? (
        <span
          id="corr-export-blocked-hint"
          className="visually-hidden"
          role="status"
          data-testid="correlation-export-blocked-hint"
        >
          {exportBlockedHint}
        </span>
      ) : null}

      {dialogOpen ? (
        <MappingBundleExportDialog busy={busy} onCancel={closeDialog} onConfirm={() => void runExport()} />
      ) : null}
    </div>
  )
}
