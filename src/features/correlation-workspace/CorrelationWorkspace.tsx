import { useEffect, useRef, useState } from 'react'
import { useAppStore } from '../../app/store.ts'
import { cs } from '../../i18n/cs.ts'
import {
  buildCorrelationEntityRows,
  getCorrelationWorkspaceSummary,
} from '../../correlation/correlationReviewModel.ts'
import { getCorrelationSource, listCorrelationSources } from '../../correlation/correlationSessionModel.ts'
import { SourceKind } from '../../domain/sourceArtifact.ts'
import {
  enterCorrelationCompletedPhase,
  enterCorrelationExportingPhase,
  enterCorrelationReviewPhase,
  focusCorrelationProblem,
  leaveCorrelationReview,
  selectCorrelationSourceWithAnnounce,
} from '../../correlation/correlationWorkspaceController.ts'
import { addCorrelationSource } from '../../correlation/correlationController.ts'
import {
  correlationSetIsUnstableForExport,
  runCorrelationExport,
} from '../../correlation/export/correlationExportController.ts'
import type { CorrelationExportScope } from '../../correlation/export/correlationExportTypes.ts'
import type { SourceSplitMeta } from '../../correlation/types.ts'
import { supportsDirectoryPicker } from '../../pcap/export/sinks.ts'
import { resolveInputFile } from '../../correlation/import/resolveInputFile.ts'
import { defaultOutputFileName } from '../../correlation/sourceLimits.ts'
import { UNIVERSAL_FILE_ACCEPT } from '../../correlation/import/correlationImportController.ts'
import { announceCorrelationSource } from '../../correlation/correlationLiveAnnouncer.ts'
import { CorrelationTextReview } from './CorrelationTextReview.tsx'
import { CorrelationPcapReview } from './CorrelationPcapReview.tsx'
import { CorrelationOccurrenceNav } from './CorrelationOccurrenceNav.tsx'
import { EmptySetPanel, SourceRail, SourceOverview } from './CorrelationWorkspacePanels.tsx'
import { CorrelationExportDialog } from './CorrelationExportDialog.tsx'
import { CorrelationToolbarActions } from './CorrelationToolbarActions.tsx'
import { Button, WorkspaceChrome } from '../../design-system/index.ts'

type AddProgress = {
  readonly current: number
  readonly total: number
  readonly fileName: string
} | null

type AddResultSummary = {
  readonly ok: number
  readonly failed: number
  readonly cancelled: boolean
} | null

function CorrelationRebuildBanner() {
  const planBusy = useAppStore((s) => s.planBusy)
  void useAppStore((s) => s.correlationEpoch)
  if (!planBusy) return null
  return (
    <div
      className="workspace-alert workspace-alert--warn"
      role="status"
      data-testid="correlation-rebuild-banner"
    >
      {cs.correlationWorkspace.rebuildBanner}
    </div>
  )
}

/** Problem-only banner. Idle ready copy lives in set-chrome meta — not a second bar. */
function CorrelationSummaryBar() {
  void useAppStore((s) => s.correlationEpoch)
  const summary = getCorrelationWorkspaceSummary()

  if (!summary.nextProblemSourceId) return null

  return (
    <div
      className="workspace-alert workspace-alert--warn"
      data-testid="correlation-summary-bar"
      role="status"
    >
      <div className="workspace-alert__body corr-summary__text">
        <strong>{cs.correlationWorkspace.problemBannerTitle}</strong>
        {summary.nextProblemReason ? <span>{summary.nextProblemReason}</span> : null}
      </div>
      <div className="workspace-alert__actions">
        <Button
          variant="secondary"
          data-testid="correlation-review-next-problem"
          onClick={() => focusCorrelationProblem()}
        >
          {cs.correlationWorkspace.reviewNextProblem}
        </Button>
      </div>
    </div>
  )
}

function CorrelationCenterPanel() {
  void useAppStore((s) => s.correlationEpoch)
  const selected = useAppStore((s) => s.selectedCorrelationSourceId)
  const sources = listCorrelationSources()

  if (sources.length === 0) return null

  if (selected === 'all') return <SourceOverview />

  const record = getCorrelationSource(selected)
  if (!record) return <p>{cs.correlationWorkspace.sourceMissing}</p>

  if (record.kind === SourceKind.Text) return <CorrelationTextReview sourceId={selected} />
  return <CorrelationPcapReview sourceId={selected} />
}

export function CorrelationWorkspace() {
  void useAppStore((s) => s.correlationEpoch)
  const selected = useAppStore((s) => s.selectedCorrelationSourceId)
  const sources = listCorrelationSources()
  const summary = getCorrelationWorkspaceSummary()
  const sharedCount = buildCorrelationEntityRows('shared').length
  const allReady = summary.reviewCount === 0
  const [exportOpen, setExportOpen] = useState(false)
  const [exportBusy, setExportBusy] = useState(false)
  const [addBusy, setAddBusy] = useState(false)
  const [addProgress, setAddProgress] = useState<AddProgress>(null)
  const [addResult, setAddResult] = useState<AddResultSummary>(null)
  const addAbortRef = useRef<AbortController | null>(null)
  const addInputRef = useRef<HTMLInputElement | null>(null)
  const multiDownloadWarning = !supportsDirectoryPicker()
  const unstable = correlationSetIsUnstableForExport() || addBusy

  useEffect(() => {
    return () => {
      addAbortRef.current?.abort()
    }
  }, [])

  const startExport = async (input: {
    scope: CorrelationExportScope
    partial: boolean
    preferDirectoryPicker: boolean
    expectedGenerationId: string | null
    expectedMappingRevision: number | null
  }) => {
    setExportBusy(true)
    setExportOpen(false)
    enterCorrelationExportingPhase()

    const result = await runCorrelationExport({
      scope: input.scope,
      currentSourceId: selected === 'all' ? null : selected,
      partial: input.partial,
      preferDirectoryPicker: input.preferDirectoryPicker,
      expectedGenerationId: input.expectedGenerationId,
      expectedMappingRevision: input.expectedMappingRevision,
    })

    setExportBusy(false)

    if (result.ok) {
      enterCorrelationCompletedPhase()
      return
    }

    useAppStore.getState().setToast({ message: result.message })

    // Never leave the user parked on a dead export screen. Cancelled/failed progress
    // already recorded completed/remaining — return to review so work can continue.
    enterCorrelationReviewPhase({ preserveSelection: true })
  }

  const addFilesToSession = async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return
    addAbortRef.current?.abort()
    const ac = new AbortController()
    addAbortRef.current = ac
    setAddBusy(true)
    setAddResult(null)

    const files = Array.from(fileList)
    let ok = 0
    let failed = 0
    let cancelled = false

    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i]!
        if (ac.signal.aborted) {
          cancelled = true
          break
        }
        setAddProgress({ current: i + 1, total: files.length, fileName: file.name })
        useAppStore.getState().setStatusMessage(cs.inputRejection.inflatingProgress)
        const resolved = await resolveInputFile(file, { signal: ac.signal })
        if (!resolved.ok) {
          failed += 1
          announceCorrelationSource(resolved.message)
          continue
        }
        const addOne = async (
          sourceFile: File,
          outputFileName: string,
          split?: SourceSplitMeta,
        ): Promise<'ok' | 'fail' | 'cancel'> => {
          const sourceId = `add-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
          const result = await addCorrelationSource(
            {
              sourceId,
              kind: resolved.kind,
              file: sourceFile,
              outputFileName,
              inputKind: 'file',
              split,
            },
            { signal: ac.signal },
          )
          if (!('ok' in result) || !result.ok) {
            if (
              ac.signal.aborted ||
              ('code' in result &&
                (result.code === 'correlation-cancelled' || result.code === 'correlation-staging-aborted'))
            ) {
              return 'cancel'
            }
            return 'fail'
          }
          selectCorrelationSourceWithAnnounce(sourceId)
          return 'ok'
        }

        if (resolved.mode === 'split') {
          let cancelledSplit = false
          for (const seg of resolved.split.segments) {
            const status = await addOne(seg.file, defaultOutputFileName(resolved.kind, seg.file.name), {
              splitGroupId: resolved.split.splitGroupId,
              splitIndex: seg.index,
              splitCount: seg.count,
              uniquePayloadStart: seg.uniquePayloadStart,
              mergeOutputBaseName: resolved.split.mergeOutputBaseName,
              format: seg.format,
            })
            if (status === 'cancel') {
              cancelled = true
              cancelledSplit = true
              break
            }
            if (status === 'fail') {
              failed += 1
              break
            }
            ok += 1
          }
          if (cancelledSplit) break
          continue
        }

        const status = await addOne(
          resolved.file,
          defaultOutputFileName(resolved.kind, resolved.file.name),
        )
        if (status === 'cancel') {
          cancelled = true
          break
        }
        if (status === 'fail') {
          failed += 1
          continue
        }
        ok += 1
      }
    } finally {
      setAddBusy(false)
      setAddProgress(null)
      addAbortRef.current = null
      useAppStore.getState().setStatusMessage('')
      if (addInputRef.current) addInputRef.current.value = ''
      setAddResult({ ok, failed, cancelled })
    }
  }

  return (
    <section className="corr-workspace" aria-labelledby="corr-workspace-title" data-testid="correlation-workspace">
      <header className="corr-workspace__chrome corr-workspace__chrome--set" data-testid="correlation-set-chrome">
        <input
          ref={addInputRef}
          type="file"
          className="visually-hidden"
          accept={UNIVERSAL_FILE_ACCEPT}
          multiple
          data-testid="correlation-add-source-input"
          aria-label={cs.correlationWorkspace.addSource}
          onChange={(e) => void addFilesToSession(e.target.files)}
        />
        <WorkspaceChrome
          testId="correlation-set-row"
          className="corr-workspace__set-row"
          context={
            <div className="corr-workspace__identity">
              <h1 id="corr-workspace-title" className="corr-workspace__title type-section-title">
                {cs.correlationWorkspace.title}
              </h1>
              <p className="corr-workspace__meta type-meta" data-testid="correlation-toolbar-meta">
                {cs.correlationWorkspace.toolbarFiles(sources.length)}
                {' · '}
                {sharedCount > 0 ? (
                  <button
                    type="button"
                    className="corr-workspace__meta-link"
                    data-testid="correlation-toolbar-shared-link"
                    title={cs.correlationWorkspace.toolbarSharedHint}
                    onClick={() => selectCorrelationSourceWithAnnounce('all')}
                  >
                    {cs.correlationWorkspace.toolbarShared(sharedCount)}
                  </button>
                ) : (
                  cs.correlationWorkspace.toolbarShared(sharedCount)
                )}
                {' · '}
                {cs.correlationWorkspace.toolbarReady(allReady)}
              </p>
            </div>
          }
          tools={
            <>
              <SourceRail
                addBusy={addBusy}
                onAddClick={() => addInputRef.current?.click()}
                onCancelAdd={() => addAbortRef.current?.abort()}
              />
              {selected !== 'all' && sources.length > 0 ? <CorrelationOccurrenceNav compact /> : null}
            </>
          }
          primary={
            <CorrelationToolbarActions
              addBusy={addBusy}
              exportBusy={exportBusy}
              readyCount={summary.readyCount}
              unstable={unstable}
              onExportOpen={() => setExportOpen(true)}
            />
          }
        />
      </header>

      <div className="workspace-alert-stack" data-testid="workspace-alert-stack">
        {/* Order: blocking rebuild → problem summary → add progress/result */}
        <CorrelationRebuildBanner />
        <CorrelationSummaryBar />
        {addBusy && addProgress ? (
          <div
            className="workspace-alert workspace-alert--info"
            role="status"
            data-testid="correlation-add-progress"
          >
            <span className="workspace-alert__body">
              {cs.correlationWorkspace.addSourceProgress(
                addProgress.current,
                addProgress.total,
                addProgress.fileName,
              )}
            </span>
            <div className="workspace-alert__actions">
              <Button
                variant="ghost"
                data-testid="correlation-add-source-cancel-inline"
                onClick={() => addAbortRef.current?.abort()}
              >
                {cs.correlationWorkspace.cancelAddSource}
              </Button>
            </div>
          </div>
        ) : null}
        {!addBusy && addResult ? (
          <div
            className={`workspace-alert ${
              addResult.cancelled || addResult.failed > 0
                ? 'workspace-alert--warn'
                : 'workspace-alert--ok'
            }`}
            role="status"
            data-testid="correlation-add-result"
          >
            <span className="workspace-alert__body">
              {addResult.cancelled
                ? cs.correlationWorkspace.addSourceCancelled
                : cs.correlationWorkspace.addSourceDone(addResult.ok, addResult.failed)}
            </span>
            <div className="workspace-alert__actions">
              <Button
                variant="ghost"
                data-testid="correlation-add-result-dismiss"
                onClick={() => setAddResult(null)}
              >
                {cs.drawer.close}
              </Button>
            </div>
          </div>
        ) : null}
      </div>

      <div className="corr-workspace__grid">
        <div className="corr-workspace__panel corr-workspace__panel--preview">
          <div className="corr-workspace__center">
            {sources.length === 0 ? (
              <EmptySetPanel
                onAddClick={() => addInputRef.current?.click()}
                onClose={() => leaveCorrelationReview()}
              />
            ) : (
              <CorrelationCenterPanel />
            )}
          </div>
        </div>
      </div>

      <p className="corr-workspace__narrow visually-hidden">{cs.correlationWorkspace.narrowHint}</p>

      <p
        id="corr-source-live"
        className="visually-hidden"
        role="status"
        aria-live="polite"
        aria-atomic="true"
        data-testid="correlation-source-live"
      />

      {exportOpen ? (
        <CorrelationExportDialog
          multiDownloadWarning={multiDownloadWarning}
          canPickDirectory={supportsDirectoryPicker()}
          busy={exportBusy}
          currentSourceId={selected === 'all' ? null : selected}
          onCancel={() => setExportOpen(false)}
          onExport={(input) => void startExport(input)}
        />
      ) : null}
    </section>
  )
}
