import { cs } from '../../i18n/cs.ts'
import { useAppStore } from '../../app/store.ts'
import { getSessionModel } from '../workspace/sessionModel.ts'
import { computeAliasSuppressedSummary } from './entityState.ts'
import { CATEGORY_LABELS } from './categoryLabels.ts'
import { resolveTextExportGate } from '../../pcap/trust/exportGate.ts'

/** Compact security status for the workspace command strip (T08 / T71 export gate). */
export function SecuritySummaryBar({ compact = false }: { readonly compact?: boolean }) {
  const sessionEpoch = useAppStore((s) => s.sessionEpoch)
  const phase = useAppStore((s) => s.phase)
  const planBusy = useAppStore((s) => s.planBusy)
  const session = sessionEpoch >= 0 ? getSessionModel() : null

  if ((phase !== 'workspace' && phase !== 'correlation-review') || !session) return null

  const suppressed = computeAliasSuppressedSummary(session.entities, session.categoryMasters)
  const gate = planBusy
    ? null
    : resolveTextExportGate({
        failedRuleIds: session.meta.failedRuleIds,
        incidentCount: session.incidents?.totalFailures ?? 0,
      })
  const noFindings = session.entities.length === 0

  // T71 — never blocked for failed rules / suppressed aliases; WITH_GAPS is informational.
  const chipLevel = planBusy ? 'blocked' : 'ok'

  const label = planBusy
    ? cs.security.recomputing
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
        noFindings && !planBusy
          ? cs.security.noFindingsHint
          : cs.security.statusDisclaimer
      }
    >
      <span className="security-chip__dot" aria-hidden />
      <span className="security-chip__label">{label}</span>
      <span className="visually-hidden" data-testid="security-disclaimer">
        {noFindings && !planBusy
          ? cs.security.noFindingsHint
          : cs.security.statusDisclaimer}
      </span>
      {gate?.gate === 'AI_READY_WITH_GAPS' && session.meta.failedRuleIds.length > 0 && !planBusy ? (
        <span className="security-chip__hint">
          {cs.security.failedRules}: {session.meta.failedRuleIds.join(', ')}
        </span>
      ) : null}
      {suppressed.entityCount > 0 && !planBusy ? (
        <details className="security-chip__details">
          <summary>
            {cs.security.exposedSummary
              .replace('{cats}', String(suppressed.categoryCount))
              .replace('{ents}', String(suppressed.entityCount))
              .replace('{occs}', String(suppressed.occurrenceCount))}
          </summary>
          <ul>
            {suppressed.categories.map((c) => (
              <li key={c.category}>
                {CATEGORY_LABELS[c.category]}: {c.entityCount} {cs.review.values},{' '}
                {c.occurrenceCount} {cs.review.occurrences}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  )
}
