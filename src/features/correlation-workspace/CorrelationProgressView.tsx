import { useEffect, useMemo, useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import { useAppStore } from '../../app/store.ts'
import { StatusChip, type StatusChipTone } from '../../components/ui/StatusChip.tsx'
import { getCorrelationProgressState } from '../../correlation/correlationProgressModel.ts'
import { cancelInitialCorrelationProcessing } from '../../correlation/correlationWorkspaceController.ts'
import { listCorrelationSources } from '../../correlation/correlationSessionModel.ts'
import { removeStagingItem } from '../../correlation/import/stagingModel.ts'
import { ProgressSplash } from '../../design-system/ProgressSplash.tsx'
import { Button } from '../../design-system/Button.tsx'

function statusTone(status: string): StatusChipTone {
  if (status === 'done') return 'ok'
  if (status === 'active') return 'active'
  if (status === 'failed') return 'error'
  return 'waiting'
}

function statusLabel(status: string): string {
  if (status === 'done') return cs.correlationProgress.statusDoneLabel
  if (status === 'active') return cs.correlationProgress.statusActiveLabel
  if (status === 'failed') return cs.correlationProgress.statusFailedLabel
  return cs.correlationProgress.statusWaitingLabel
}

function rowPercent(status: string, done: number | null, total: number | null): number | null {
  if (status === 'done') return 100
  if (status !== 'active') return 0
  if (total != null && total > 0 && done != null) {
    return Math.min(100, Math.round((done / total) * 100))
  }
  return null
}

function useDisplayPercent(real: number, startedAt: number, active: boolean): number {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (!active) return
    const id = window.setInterval(() => setTick((t) => t + 1), 1000)
    return () => window.clearInterval(id)
  }, [active])
  return useMemo(() => {
    if (!active) return real
    const elapsed = startedAt > 0 ? (Date.now() - startedAt) / 1000 : 0
    const pulse = real < 95 ? Math.min(22, elapsed * 1.8) : 0
    return Math.min(99, Math.max(real, Math.round(pulse)))
    // eslint-disable-next-line react-hooks/exhaustive-deps -- tick drives periodic refresh
  }, [real, startedAt, active, tick])
}

const TIP_COUNT = cs.correlationProgress.tips.length

export function CorrelationProgressView() {
  void useAppStore((s) => s.correlationEpoch)
  const progress = getCorrelationProgressState()
  const failedSource = listCorrelationSources().find((s) => s.phase === 'failed')
  const displayPercent = useDisplayPercent(progress.aggregatePercent, progress.startedAt, progress.active)
  const [elapsed, setElapsed] = useState(0)
  const [tipIndex, setTipIndex] = useState(0)

  useEffect(() => {
    if (progress.startedAt <= 0) return
    const tick = () => setElapsed(Math.max(0, Math.round((Date.now() - progress.startedAt) / 1000)))
    tick()
    const id = window.setInterval(tick, 1000)
    return () => window.clearInterval(id)
  }, [progress.startedAt])

  useEffect(() => {
    if (!progress.active || TIP_COUNT <= 0) return
    const id = window.setInterval(() => {
      setTipIndex((i) => (i + 1) % TIP_COUNT)
    }, 3200)
    return () => window.clearInterval(id)
  }, [progress.active])

  const indeterminate = progress.active && displayPercent < 8
  const tip = cs.correlationProgress.tips[tipIndex % TIP_COUNT]

  return (
    <ProgressSplash
      className="corr-progress corr-progress--splash"
      testId="correlation-progress"
      eyebrow={cs.correlationProgress.working}
      title={cs.correlationProgress.title}
      percent={displayPercent}
      indeterminate={indeterminate}
      detail={progress.phaseLabel || undefined}
      tip={tip}
      elapsedSec={elapsed}
      onCancel={failedSource ? undefined : () => void cancelInitialCorrelationProcessing()}
      cancelLabel={cs.correlationProgress.cancel}
      cancelTestId="corr-cancel-processing"
    >
      <ul className="progress-splash__sources corr-progress__sources" data-testid="correlation-progress-sources">
        {progress.sources.map((row) => {
          const pct = rowPercent(row.status, row.done, row.total)
          return (
            <li key={row.sourceId} className={`corr-progress__row corr-progress__row--${row.status}`}>
              <StatusChip tone={statusTone(row.status)} label={statusLabel(row.status)} compact />
              <div className="corr-progress__row-main">
                <span className="corr-progress__name" title={row.fileName}>
                  {row.fileName}
                </span>
                <div className="corr-progress__row-bar" aria-hidden="true">
                  <div
                    className={`corr-progress__row-bar-fill${
                      row.status === 'active' && pct == null ? ' corr-progress__row-bar-fill--indeterminate' : ''
                    }`}
                    style={pct == null ? undefined : { width: `${Math.max(row.status === 'active' ? 8 : 0, pct)}%` }}
                  />
                </div>
              </div>
              <span className="corr-progress__detail">{row.phaseLabel}</span>
              {row.valueCount != null ? (
                <span className="corr-progress__values">{cs.correlationProgress.values(row.valueCount)}</span>
              ) : null}
            </li>
          )
        })}
      </ul>

      {failedSource ? (
        <div className="corr-progress__recovery" role="alert" data-testid="corr-progress-recovery">
          <p>{failedSource.errorMessage ?? cs.correlationProgress.sourceFailed}</p>
          <div className="corr-progress__recovery-actions">
            <Button
              variant="primary"
              data-testid="corr-remove-and-continue"
              onClick={() => {
                removeStagingItem(failedSource.sourceId)
                void cancelInitialCorrelationProcessing()
              }}
            >
              {cs.correlationProgress.removeAndContinue}
            </Button>
            <Button
              variant="secondary"
              data-testid="corr-cancel-to-staging"
              onClick={() => void cancelInitialCorrelationProcessing()}
            >
              {cs.correlationStaging.back}
            </Button>
          </div>
        </div>
      ) : null}

      <p className="visually-hidden" role="status" aria-live="polite">
        {progress.liveAnnouncement ?? ''}
      </p>
    </ProgressSplash>
  )
}
