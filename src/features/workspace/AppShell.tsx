import { lazy, Suspense, useEffect, useRef } from 'react'
import { AppHeader } from '../../components/ui/AppHeader.tsx'
import { FirstVisitTour } from '../../components/ui/FirstVisitTour.tsx'
import { AppToast } from '../../components/ui/AppToast.tsx'
import { HelpPanel } from '../../components/ui/HelpPanel.tsx'
import { AnonymizationDocsPanel } from '../../components/ui/AnonymizationDocsPanel.tsx'
import { MultiSourceDropzone } from '../correlation-staging/MultiSourceDropzone.tsx'
import { CorrelationStagingView } from '../correlation-staging/CorrelationStagingView.tsx'
import { CorrelationProgressView } from '../correlation-workspace/CorrelationProgressView.tsx'
import { CorrelationWorkspace } from '../correlation-workspace/CorrelationWorkspace.tsx'
import { CorrelationExportProgress } from '../correlation-workspace/CorrelationExportProgress.tsx'
import { CorrelationCompletionView } from '../correlation-workspace/CorrelationCompletionView.tsx'
import { WorkspaceView } from './WorkspaceView.tsx'
import { useAppStore } from '../../app/store.ts'
import {
  handleUniversalFileDrop,
  UNIVERSAL_FILE_ACCEPT,
} from '../../correlation/import/correlationImportController.ts'
import { cancelCorrelationExport } from '../../correlation/export/correlationExportController.ts'
import { getCorrelationExportProgress } from '../../correlation/export/correlationExportModel.ts'
import { enterCorrelationReviewPhase } from '../../correlation/correlationWorkspaceController.ts'
import { ImportCancelledError } from '../import-log/streamImport.ts'
import { markSessionAnalysisFailed } from './sessionModel.ts'
import { getDualLogBridge } from './editorBridge.ts'
import { cs } from '../../i18n/cs.ts'
import { ResolveOnlyView } from '../resolve-only/ResolveOnlyView.tsx'
import { ResourceConflictDialog } from './ResourceConflictDialog.tsx'
import { cancelResourceConflict } from '../../app/resourceConflictPrompt.ts'
import { usePcapStore } from '../../pcap/ui/pcapStore.ts'

const PcapModeRoot = lazy(() =>
  import('../../app/shell/PcapModeRoot.tsx').then((m) => ({ default: m.PcapModeRoot })),
)

declare global {
  interface Window {
    __RND_LOG_ANONYMIZER_E2E__?: {
      markExportBlocked: () => boolean
    }
  }
}

export function AppShell() {
  const phase = useAppStore((s) => s.phase)
  const activeMode = useAppStore((s) => s.activeMode)
  const pcapPhase = usePcapStore((s) => s.phase)
  const statusMessage = useAppStore((s) => s.statusMessage)
  const fileFocusRef = useRef<HTMLButtonElement>(null)
  const persistentFileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (phase === 'empty') {
      useAppStore.getState().setStatusMessage(cs.status.ready)
    }
  }, [phase])

  useEffect(() => {
    // Playwright e2e harness (offline-only; mutates in-memory session flags).
    window.__RND_LOG_ANONYMIZER_E2E__ = {
      markExportBlocked: () => {
        const ok = markSessionAnalysisFailed(['e2e-timeout'])
        if (ok) useAppStore.getState().bumpSessionEpoch()
        return ok
      },
    }
    return () => {
      delete window.__RND_LOG_ANONYMIZER_E2E__
    }
  }, [])

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const mod = event.metaKey || event.ctrlKey
      if (mod && event.key.toLowerCase() === 'o') {
        event.preventDefault()
        persistentFileRef.current?.click()
        return
      }
      if (mod && event.key.toLowerCase() === 'f') {
        event.preventDefault()
        const store = useAppStore.getState()
        if (store.phase !== 'workspace' && store.phase !== 'correlation-review') return
        getDualLogBridge()?.focusSearch()
        return
      }
      if (mod && event.shiftKey && (event.key.toLowerCase() === 'c' || event.code === 'KeyC')) {
        event.preventDefault()
        const store = useAppStore.getState()
        if (store.phase !== 'workspace') return
        document.querySelector<HTMLButtonElement>('[data-testid="export-copy"]')?.click()
        return
      }
      if (mod && event.shiftKey && event.key.toLowerCase() === 'r') {
        event.preventDefault()
        const store = useAppStore.getState()
        if (store.phase !== 'workspace' && store.phase !== 'importing') return
        store.setReviewTab('rules')
        store.setEditingRuleId(null)
        store.setRuleFormOpen(true)
        return
      }
      // Alt+Z — toggle wrap (ARCHITECTURE §13)
      if (event.altKey && !mod && event.key.toLowerCase() === 'z') {
        event.preventDefault()
        const store = useAppStore.getState()
        store.setWrapEnabled(!store.wrapEnabled)
        return
      }
      if (event.key === 'Escape') {
        const store = useAppStore.getState()
        if (store.resourceConflict) {
          event.preventDefault()
          cancelResourceConflict()
          return
        }
        if (store.helpOpen) {
          // HelpPanel owns Escape via useModalFocusTrap (restore focus to opener).
          return
        }
        if (store.docsOpen) {
          // AnonymizationDocsPanel owns Escape via useModalFocusTrap (restore focus to opener).
          return
        }
        if (store.profileDialog !== 'none') {
          event.preventDefault()
          store.setProfileDialog('none')
          store.setPendingSwitchProfileId(null)
          return
        }
        if (store.ruleFormOpen) {
          event.preventDefault()
          store.setRuleFormOpen(false)
          store.setEditingRuleId(null)
          return
        }
        const modalCancelIds = [
          'resource-conflict-cancel',
          'pcap-export-confirm-cancel',
          'pcap-replace-cancel',
        ] as const
        for (const id of modalCancelIds) {
          const btn = document.querySelector<HTMLButtonElement>(`[data-testid="${id}"]`)
          if (btn) {
            event.preventDefault()
            btn.click()
            return
          }
        }
        const exposedCancel = document.querySelector<HTMLButtonElement>(
          '[data-testid="exposed-export-dialog"] .btn--ghost',
        )
        if (exposedCancel) {
          event.preventDefault()
          exposedCancel.click()
        }
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  const openFilePicker = () => {
    persistentFileRef.current?.click()
    fileFocusRef.current?.focus()
  }

  const onPersistentFile = (files: FileList | null) => {
    if (!files?.length) return
    void (async () => {
      try {
        await handleUniversalFileDrop([...files])
      } catch (err) {
        if (err instanceof ImportCancelledError) return
        const message = err instanceof Error ? err.message : cs.errors.importFailed
        useAppStore.getState().setLastError(message)
        useAppStore.getState().setPhase('empty')
      } finally {
        if (persistentFileRef.current) persistentFileRef.current.value = ''
      }
    })()
  }

  const showEmpty = phase === 'empty'
  const showPcapShell = activeMode === 'pcap' && pcapPhase !== 'empty'
  const showLanding = showEmpty && !showPcapShell
  const showStaging = phase === 'correlation-staging'
  const showCorrelationProcessing = phase === 'correlation-processing'
  const showCorrelationReview = phase === 'correlation-review'
  const showCorrelationExporting = phase === 'correlation-exporting'
  const showCorrelationCompleted = phase === 'correlation-completed'
  const showWorkspace = phase === 'importing' || phase === 'workspace'
  const showResolveOnly = phase === 'resolve-only'
  // Forensic Bench step 5 — workspace density is always compact.
  // Comfortable is reserved for gallery / explicit a11y overrides outside the shell.
  const density = 'compact' as const

  const inMultiSource =
    showStaging ||
    showCorrelationProcessing ||
    showCorrelationReview ||
    showCorrelationExporting ||
    showCorrelationCompleted

  return (
    <div className="app-shell" data-density={density} data-design="forensic-bench">
      <a className="skip-link" href="#main">
        {cs.skipToContent}
      </a>
      <AppHeader />
      <main id="main" className="app-main" tabIndex={-1}>
        {showResolveOnly ? <ResolveOnlyView /> : null}
        {showStaging ? <CorrelationStagingView /> : null}
        {showCorrelationProcessing ? <CorrelationProgressView /> : null}
        {showCorrelationReview ? <CorrelationWorkspace /> : null}
        {showCorrelationExporting ? (
          <CorrelationExportProgress
            onCancel={() => {
              const progress = getCorrelationExportProgress()
              if (
                progress.phase === 'cancelled' ||
                progress.phase === 'error' ||
                progress.phase === 'done' ||
                progress.phase === 'idle'
              ) {
                enterCorrelationReviewPhase({ preserveSelection: true })
                return
              }
              cancelCorrelationExport()
            }}
          />
        ) : null}
        {showCorrelationCompleted ? <CorrelationCompletionView /> : null}
        {!showResolveOnly && !inMultiSource && showLanding ? <MultiSourceDropzone /> : null}
        {!showResolveOnly && !inMultiSource && showWorkspace ? <WorkspaceView /> : null}
        {!showResolveOnly && !inMultiSource && showPcapShell && !showWorkspace ? (
          <Suspense fallback={null}>
            <PcapModeRoot />
          </Suspense>
        ) : null}
      </main>
      <p
        className="visually-hidden"
        role="status"
        aria-live="polite"
        aria-label={cs.a11y.liveStatus}
      >
        {statusMessage || cs.status.ready}
      </p>
      <button
        id="open-log-proxy"
        ref={fileFocusRef}
        type="button"
        className="visually-hidden"
        tabIndex={-1}
        aria-hidden="true"
        onClick={openFilePicker}
      >
        {cs.header.openLog}
      </button>
      <input
        ref={persistentFileRef}
        className="visually-hidden"
        type="file"
        accept={UNIVERSAL_FILE_ACCEPT}
        multiple
        tabIndex={-1}
        aria-label={cs.correlationStaging.chooseFiles}
        data-testid="persistent-file-input"
        onChange={(e) => onPersistentFile(e.target.files)}
      />
      <HelpPanel />
      <AnonymizationDocsPanel />
      <AppToast />
      <ResourceConflictDialog />
      <FirstVisitTour />
    </div>
  )
}
