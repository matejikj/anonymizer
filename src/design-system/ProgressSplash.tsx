import type { ReactNode } from 'react'
import { Button } from './Button.tsx'
import { Progress } from './Controls.tsx'

/**
 * Lab progress — Forensic Bench processing state (not a brand splash).
 * Shared by text / PCAP / correlation.
 */
export function ProgressSplash({
  title,
  eyebrow,
  fileName,
  percent,
  indeterminate,
  detail,
  tip,
  elapsedSec,
  onCancel,
  cancelLabel,
  cancelTestId = 'progress-cancel',
  barSlot,
  children,
  testId,
  className,
}: {
  readonly title: string
  readonly eyebrow?: string
  readonly fileName?: string | null
  readonly percent?: number | null
  readonly indeterminate?: boolean
  readonly detail?: string
  readonly tip?: string
  readonly elapsedSec?: number
  readonly onCancel?: () => void
  readonly cancelLabel?: string
  readonly cancelTestId?: string
  /** Replaces the default single bar+percent — e.g. a multi-step stepper bar. */
  readonly barSlot?: ReactNode
  readonly children?: ReactNode
  readonly testId?: string
  readonly className?: string
}) {
  const pct = percent == null ? null : Math.max(0, Math.min(100, percent))
  const showIndeterminate = indeterminate || pct == null || pct < 8

  return (
    <div
      className={['progress-splash', className].filter(Boolean).join(' ')}
      role="status"
      aria-live="polite"
      aria-busy="true"
      data-testid={testId}
    >
      {eyebrow ? <p className="progress-splash__eyebrow type-meta">{eyebrow}</p> : null}
      <h2 className="progress-splash__title type-page-title">{title}</h2>

      {fileName ? (
        <p className="progress-splash__file type-mono" title={fileName}>
          {fileName}
        </p>
      ) : null}

      <div className="progress-splash__bar">
        {barSlot ?? (
          <>
            {showIndeterminate ? (
              <div className="progress-splash__indeterminate" aria-hidden="true" />
            ) : (
              <Progress value={pct ?? 0} max={100} label={detail} />
            )}
            {pct != null && !showIndeterminate ? (
              <p className="progress-splash__percent type-mono">{pct} %</p>
            ) : null}
          </>
        )}
      </div>

      {detail && (barSlot || showIndeterminate) ? (
        <p className="progress-splash__detail type-meta">{detail}</p>
      ) : null}
      {tip ? <p className="progress-splash__tip type-meta">{tip}</p> : null}
      {elapsedSec != null && elapsedSec > 0 ? (
        <p className="progress-splash__elapsed type-meta">{elapsedSec} s</p>
      ) : null}

      {children}

      {onCancel ? (
        <div className="progress-splash__actions" key="progress-splash-actions">
          <Button
            key={cancelTestId}
            variant="ghost"
            onClick={onCancel}
            data-testid={cancelTestId}
          >
            {cancelLabel ?? 'Zrušit'}
          </Button>
        </div>
      ) : null}
    </div>
  )
}
