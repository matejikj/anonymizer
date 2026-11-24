import { useRef, useState } from 'react'
import { useAppStore } from '../../app/store.ts'
import { getSessionModel } from '../workspace/sessionModel.ts'
import {
  computeExposedSummary,
  computeSecurityLevel,
} from '../review/entityState.ts'
import {
  copyAnonymizedBlob,
  downloadBlob,
  ExportCancelledError,
  runChunkedExport,
  type ExportProgress,
} from './exportCoordinator.ts'
import { ExposedExportDialog } from './ExposedExportDialog.tsx'
import { MappingBundleActions } from '../mapping-bundle/MappingBundleActions.tsx'
import { Button } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'

type PendingAction = 'copy' | 'download' | null

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`
}

/** Export actions for the command strip — stable hierarchy matching PCAP. */
export function ExportBar() {
  const sessionEpoch = useAppStore((s) => s.sessionEpoch)
  const phase = useAppStore((s) => s.phase)
  const planBusy = useAppStore((s) => s.planBusy)
  const session = sessionEpoch >= 0 ? getSessionModel() : null
  const [progress, setProgress] = useState<ExportProgress | null>(null)
  const [pending, setPending] = useState<PendingAction>(null)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [allowLargeStringCopy, setAllowLargeStringCopy] = useState(false)
  const [heldBlob, setHeldBlob] = useState<{ blob: Blob; fileName: string } | null>(null)
  const abortRef = useRef<AbortController | null>(null)

  if (phase !== 'workspace' || !session) return null

  const exposed = computeExposedSummary(session.entities, session.categoryMasters)
  const level = computeSecurityLevel({
    analysisDone: true,
    failedRuleIds: session.meta.failedRuleIds,
    exposed,
  })
  const blocked = level === 'blocked'
  const large = session.meta.mode === 'large'
  const busy = progress != null && progress.phase !== 'done' && progress.phase !== 'error'
  const exportDisabled = blocked || busy || planBusy
  const blockedReasonId = exportDisabled ? 'export-blocked-hint' : undefined

  const startExport = async (action: 'copy' | 'download', forceExposed = false) => {
    if (blocked || planBusy) return
    if (level === 'exposed' && !forceExposed) {
      setPending(action)
      setConfirmOpen(true)
      return
    }
    setConfirmOpen(false)
    setPending(null)
    setHeldBlob(null)

    abortRef.current?.abort()
    const ac = new AbortController()
    abortRef.current = ac
    setProgress({
      phase: 'preparing',
      processedBytes: 0,
      totalBytes: session.meta.byteLength,
      message: cs.export.preparing,
    })

    try {
      const result = await runChunkedExport({
        signal: ac.signal,
        onProgress: setProgress,
      })
      if (action === 'download') {
        downloadBlob(result.fileName, result.blob)
        useAppStore.getState().setToast({ message: cs.export.downloadStarted })
      } else {
        const copyResult = await copyAnonymizedBlob(result.blob, {
          allowStringFallback: !large || allowLargeStringCopy,
        })
        if (copyResult.ok) {
          useAppStore.getState().setToast({ message: cs.export.copied })
        } else {
          setHeldBlob({ blob: result.blob, fileName: result.fileName })
          useAppStore.getState().setToast({
            message: cs.export.clipboardFailed,
          })
        }
      }
      setProgress(null)
    } catch (err) {
      if (err instanceof ExportCancelledError) {
        setProgress({
          phase: 'cancelled',
          processedBytes: 0,
          totalBytes: session.meta.byteLength,
          message: cs.export.cancelled,
        })
        useAppStore.getState().setToast({ message: cs.export.cancelled })
        return
      }
      const message = err instanceof Error ? err.message : cs.export.failed
      setProgress({
        phase: 'error',
        processedBytes: 0,
        totalBytes: session.meta.byteLength,
        message,
      })
      useAppStore.getState().setToast({ message })
    }
  }

  return (
    <div className="command-strip__export" data-testid="export-bar">
      {progress && busy ? (
        <div className="command-strip__export-progress" data-testid="export-progress">
          <span>{progress.message}</span>
          <Button variant="ghost" data-testid="export-cancel" onClick={() => abortRef.current?.abort()}>
            {cs.export.cancel}
          </Button>
        </div>
      ) : null}

      {large ? (
        <p className="command-strip__warn" data-testid="export-string-warn">
          {cs.export.stringFallbackWarn} ({formatBytes(session.meta.byteLength)})
        </p>
      ) : null}

      {heldBlob ? (
        <div className="command-strip__held" data-testid="export-held-blob">
          <span>{cs.export.heldBlob}</span>
          <Button
            variant="secondary"
            data-testid="export-download-held"
            onClick={() => {
              downloadBlob(heldBlob.fileName, heldBlob.blob)
              setHeldBlob(null)
              useAppStore.getState().setToast({ message: cs.export.downloadStarted })
            }}
          >
            {cs.export.downloadHeld}
          </Button>
          {large ? (
            <Button
              variant="ghost"
              data-testid="export-allow-string-copy"
              onClick={() => {
                const held = heldBlob
                if (!held) return
                setAllowLargeStringCopy(true)
                void (async () => {
                  const copyResult = await copyAnonymizedBlob(held.blob, {
                    allowStringFallback: true,
                  })
                  if (copyResult.ok) {
                    setHeldBlob(null)
                    useAppStore.getState().setToast({ message: cs.export.copied })
                  }
                })()
              }}
            >
              {cs.export.copyAsStringAnyway}
            </Button>
          ) : null}
        </div>
      ) : null}

      {exportDisabled ? (
        <p className="command-strip__blocked" role="status" id="export-blocked-hint" data-testid="export-blocked-hint">
          {planBusy ? cs.export.recomputingHint : cs.export.blockedHint}
        </p>
      ) : null}

      <div
        className="command-strip__export-actions"
        role="group"
        aria-label={cs.export.resultGroupLabel}
      >
        <MappingBundleActions
          mode="text"
          showImport={false}
          showExport
          presentation="toolbar"
          disabled={planBusy}
          exportTestId="mapping-bundle-export-open"
        />
        <Button
          variant="secondary"
          data-testid="export-copy"
          disabled={exportDisabled}
          aria-describedby={blockedReasonId}
          onClick={() => void startExport('copy')}
        >
          {cs.export.copyResult}
        </Button>
        <Button
          variant="primary"
          data-testid="export-download"
          disabled={exportDisabled}
          aria-describedby={blockedReasonId}
          onClick={() => void startExport('download')}
        >
          {cs.export.downloadShort}
        </Button>
      </div>

      {confirmOpen ? (
        <ExposedExportDialog
          exposed={exposed}
          onCancel={() => {
            setConfirmOpen(false)
            setPending(null)
          }}
          onConfirm={() => {
            const action = pending ?? 'download'
            void startExport(action, true)
          }}
        />
      ) : null}
    </div>
  )
}
