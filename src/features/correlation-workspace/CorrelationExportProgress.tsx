import { useAppStore } from '../../app/store.ts'
import { IconCheck, IconCircle } from '../../components/ui/icons.tsx'
import { cs } from '../../i18n/cs.ts'
import { getCorrelationExportProgress } from '../../correlation/export/correlationExportModel.ts'
import { Button } from '../../design-system/index.ts'

export function CorrelationExportProgress(props: { onCancel: () => void }) {
  void useAppStore((s) => s.correlationEpoch)
  const progress = getCorrelationExportProgress()
  const cancelled = progress.phase === 'cancelled'
  const errored = progress.phase === 'error'
  const finishedAbnormally = cancelled || errored

  return (
    <section className="corr-export-progress" data-testid="correlation-export-progress" aria-live="polite">
      <h2 className="type-page-title">{cs.correlationExport.progressTitle}</h2>
      <p>{cs.correlationExport.fileProgress(progress.fileIndex, progress.fileTotal)}</p>
      {progress.currentFileName ? (
        <p className="corr-export-progress__file" data-testid="correlation-export-current">
          {progress.currentFileName}
        </p>
      ) : null}
      <p className="corr-export-progress__phase">{progress.currentMessage}</p>

      {progress.completedFiles.length > 0 ? (
        <div data-testid="correlation-export-completed">
          <h3>{cs.correlationExport.completedHeading}</h3>
          <ul className="corr-export__file-list">
            {progress.completedFiles.map((name) => (
              <li key={name} className="corr-completion__file-row">
                <IconCheck className="corr-completion__check" aria-hidden="true" />
                <span>{name}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {finishedAbnormally && progress.remainingFiles.length > 0 ? (
        <div data-testid="correlation-export-remaining">
          <h3>{cs.correlationExport.remainingHeading}</h3>
          <ul className="corr-export__file-list">
            {progress.remainingFiles.map((name) => (
              <li key={name} className="corr-completion__file-row">
                <IconCircle className="corr-completion__check" aria-hidden="true" />
                <span>{name}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {!finishedAbnormally && progress.phase === 'exporting' && progress.currentFileName ? (
        <div data-testid="correlation-export-in-progress">
          <h3>{cs.correlationExport.inProgressHeading}</h3>
          <p>{progress.currentFileName}</p>
        </div>
      ) : null}

      {!finishedAbnormally ? (
        <Button variant="ghost" data-testid="correlation-export-cancel" onClick={props.onCancel}>
          {cs.correlationExport.cancelExport}
        </Button>
      ) : (
        <Button variant="secondary" data-testid="correlation-export-back-review" onClick={props.onCancel}>
          {cs.correlationExport.backToReview}
        </Button>
      )}
    </section>
  )
}
