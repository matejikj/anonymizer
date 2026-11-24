import { cs } from '../../i18n/cs.ts'
import { useAppStore } from '../../app/store.ts'
import { getSessionModel } from '../workspace/sessionModel.ts'
import { computeExposedSummary } from './entityState.ts'
import { CATEGORY_LABELS } from './categoryLabels.ts'
import { resolveTextExportGate } from '../../pcap/trust/exportGate.ts'

/** Compact security status for the workspace command strip (T08 three-state gate). */
export function SecuritySummaryBar({ compact = false }: { readonly compact?: boolean }) {
  const sessionEpoch = useAppStore((s) => s.sessionEpoch)
  const phase = useAppStore((s) => s.phase)
  const planBusy = useAppStore((s) => s.planBusy)
  const session = sessionEpoch >= 0 ? getSessionModel() : null

  if ((phase !== 'workspace' && phase !== 'correlation-review') || !session) return null

  const exposed = computeExposedSummary(session.entities, session.categoryMasters)
  const gate = planBusy
    ? null
    : resolveTextExportGate({
        failedRuleIds: session.meta.failedRuleIds,
        incidentCount: session.incidents?.totalFailures ?? 0,
        exposedEntityCount: exposed.entityCount,
      })
  const noFindings = session.entities.length === 0

  const chipLevel = planBusy
    ? 'blocked'
    : gate?.gate === 'NOT_AI_READY'
      ? session.meta.failedRuleIds.length > 0
        ? 'blocked'
        : 'exposed'
      : gate?.gate === 'AI_READY_WITH_GAPS'
        ? 'warn'
        : noFindings
          ? 'ok'
          : 'ok'

  const label = planBusy
    ? cs.security.recomputing
    : gate?.gate === 'NOT_AI_READY'
      ? session.meta.failedRuleIds.length > 0
        ? cs.security.blocked
        : cs.security.someOriginal
      : noFindings
        ? cs.security.noFindings
        : gate?.gate === 'AI_READY_WITH_GAPS'
          ? cs.security.aiReadyWithGaps
          : cs.security.allReplaced

  return (
    <div
      className={`security-chip security-chip--${chipLevel}${compact ? ' security-chip--compact' : ''}`}
      role="status"
      data-testid="security-bar"
      data-level={chipLevel}
      data-gate={gate?.gate ?? (planBusy ? 'busy' : undefined)}
      data-no-findings={noFindings || undefined}
      title={
        noFindings && !planBusy && chipLevel !== 'blocked'
          ? cs.security.noFindingsHint
          : cs.security.statusDisclaimer
      }
    >
      <span className="security-chip__dot" aria-hidden />
      <span className="security-chip__label">{label}</span>
      <span className="visually-hidden" data-testid="security-disclaimer">
        {noFindings && !planBusy && chipLevel !== 'blocked'
          ? cs.security.noFindingsHint
          : cs.security.statusDisclaimer}
      </span>
      {gate?.gate === 'NOT_AI_READY' && exposed.entityCount > 0 && !planBusy ? (
        <details className="security-chip__details">
          <summary>
            {cs.security.exposedSummary
              .replace('{cats}', String(exposed.categoryCount))
              .replace('{ents}', String(exposed.entityCount))
              .replace('{occs}', String(exposed.occurrenceCount))}
          </summary>
          <ul>
            {exposed.categories.map((c) => (
              <li key={c.category}>
                {CATEGORY_LABELS[c.category]}: {c.entityCount} {cs.review.values},{' '}
                {c.occurrenceCount} {cs.review.occurrences}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
      {chipLevel === 'blocked' && !planBusy && session.meta.failedRuleIds.length > 0 ? (
        <span className="security-chip__hint">
          {cs.security.failedRules}: {session.meta.failedRuleIds.join(', ')}
        </span>
      ) : null}
    </div>
  )
}
