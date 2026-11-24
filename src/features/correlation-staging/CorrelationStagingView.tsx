import { useId, useRef, useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import { useAppStore } from '../../app/store.ts'
import {
  addMoreStagingFiles,
  applyRecommendedStagingResolutions,
  canConfirmCorrelationStaging,
  confirmCorrelationStaging,
  continueCorrelationStagingWithSingleFile,
  getStagingConfirmBlockedReason,
  getStagingProfileCompatibilityReport,
  leaveCorrelationStaging,
  resolveStagingProfileConflict,
  UNIVERSAL_FILE_ACCEPT,
} from '../../correlation/import/correlationImportController.ts'
import {
  buildStagingSummary,
  getStagingItems,
  removeStagingItem,
} from '../../correlation/import/stagingModel.ts'
import { CorrelationCompatibilityBanner } from './CorrelationCompatibilityBanner.tsx'
import { focusAfterRemove } from './SourceStagingRow.tsx'
import { SourceStagingList } from './SourceStagingList.tsx'
import { Button } from '../../design-system/index.ts'

export function CorrelationStagingView() {
  const inputId = useId()
  const fileRef = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)
  void useAppStore((s) => s.correlationEpoch)

  const items = getStagingItems()
  const summary = buildStagingSummary(items)
  const report = getStagingProfileCompatibilityReport()
  const blockedReason = getStagingConfirmBlockedReason()
  const canConfirm = canConfirmCorrelationStaging() && !busy
  const showSingleFileHint = summary.readyCount === 1 && !summary.aggregateOverLimit

  const onRemove = (id: string) => {
    const idx = items.findIndex((i) => i.id === id)
    const nextId = items[idx + 1]?.id ?? items[idx - 1]?.id ?? null
    removeStagingItem(id)
    useAppStore.getState().bumpCorrelationEpoch()
    focusAfterRemove(nextId)
  }

  const onAddFiles = () => fileRef.current?.click()

  const onFilesSelected = async (files: FileList | null) => {
    if (!files?.length) return
    setLocalError(null)
    await addMoreStagingFiles([...files])
    if (fileRef.current) fileRef.current.value = ''
  }

  const onConfirm = async () => {
    setLocalError(null)
    setBusy(true)
    try {
      const result = await confirmCorrelationStaging()
      if (!result.ok) {
        if (!result.cancelled) setLocalError(result.message)
        return
      }
      useAppStore.getState().setStatusMessage(cs.correlationWorkspace.readyMessage(result.sourceCount))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="staging-view" aria-labelledby="staging-view-title" data-testid="correlation-staging">
      <div className="staging-view__toolbar">
        <Button variant="ghost" data-testid="staging-back" onClick={() => leaveCorrelationStaging()}>
          {cs.correlationStaging.back}
        </Button>
      </div>

      <SourceStagingList items={items} summary={summary} onRemove={onRemove} />

      <CorrelationCompatibilityBanner
        report={report}
        onApplyRecommended={() => {
          applyRecommendedStagingResolutions()
        }}
        onResolve={(category, resolution) => {
          resolveStagingProfileConflict(category, resolution)
        }}
      />

      {localError ? (
        <p className="staging-view__error" role="alert" data-testid="staging-error">
          {localError}
        </p>
      ) : null}

      {showSingleFileHint ? (
        <div className="staging-view__single-hint" data-testid="staging-single-file-hint">
          <Button
            variant="secondary"
            data-testid="staging-continue-single"
            disabled={busy}
            onClick={() => {
              void continueCorrelationStagingWithSingleFile().then((result) => {
                if (!result.ok) setLocalError(result.message)
              })
            }}
          >
            {cs.correlationStaging.continueSingle}
          </Button>
        </div>
      ) : null}

      <div className="staging-view__actions">
        <Button variant="secondary" data-testid="staging-add-files" onClick={onAddFiles} disabled={busy}>
          {cs.correlationStaging.addFiles}
        </Button>
        <div className="staging-view__primary">
          <Button
            variant="primary"
            data-testid="staging-confirm"
            disabled={!canConfirm}
            busy={busy}
            aria-describedby={!canConfirm && blockedReason ? 'staging-blocked-reason' : undefined}
            onClick={() => void onConfirm()}
          >
            {cs.correlationStaging.confirm}
          </Button>
          {!canConfirm && blockedReason ? (
            <p
              id="staging-blocked-reason"
              className="staging-view__blocked"
              role="status"
              data-testid="staging-blocked-reason"
            >
              {blockedReason}
            </p>
          ) : null}
        </div>
      </div>

      <label className="visually-hidden" htmlFor={inputId}>
        {cs.correlationStaging.addFiles}
      </label>
      <input
        id={inputId}
        ref={fileRef}
        className="visually-hidden"
        type="file"
        accept={UNIVERSAL_FILE_ACCEPT}
        multiple
        onChange={(e) => void onFilesSelected(e.target.files)}
      />
    </section>
  )
}
