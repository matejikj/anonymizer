import { cs } from '../../i18n/cs.ts'
import { stepFlatOccurrence } from '../../correlation/correlationReviewModel.ts'
import { jumpToCorrelationOccurrenceAtCursor } from '../../correlation/correlationWorkspaceController.ts'
import { Button } from '../../design-system/index.ts'

export interface CorrelationOccurrenceNavProps {
  readonly compact?: boolean
}

/** Cross-file shared-value occurrence stepping — distinct from in-file findings nav. */
export function CorrelationOccurrenceNav({ compact = false }: CorrelationOccurrenceNavProps) {
  const step = (delta: 1 | -1) => {
    const ref = stepFlatOccurrence(delta)
    if (ref) jumpToCorrelationOccurrenceAtCursor(ref)
  }

  return (
    <div
      className={compact ? 'corr-occ-nav corr-occ-nav--compact' : 'corr-occ-nav'}
      data-testid="correlation-occurrence-nav"
      role="group"
      aria-label={cs.correlationWorkspace.acrossFilesNav}
    >
      {!compact ? (
        <span className="corr-occ-nav__label">{cs.correlationWorkspace.acrossFilesNav}</span>
      ) : null}
      <Button
        variant="ghost"
        size="tiny"
        aria-label={cs.correlationWorkspace.prevOccurrence}
        data-testid="correlation-occ-prev"
        onClick={() => step(-1)}
      >
        {compact ? cs.correlationWorkspace.prevOccurrenceShort : cs.correlationWorkspace.prevOccurrence}
      </Button>
      <Button
        variant="ghost"
        size="tiny"
        aria-label={cs.correlationWorkspace.nextOccurrence}
        data-testid="correlation-occ-next"
        onClick={() => step(1)}
      >
        {compact ? cs.correlationWorkspace.nextOccurrenceShort : cs.correlationWorkspace.nextOccurrence}
      </Button>
    </div>
  )
}
