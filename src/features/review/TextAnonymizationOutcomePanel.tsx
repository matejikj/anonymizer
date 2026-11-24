/**
 * T10 — text-mode anonymization outcome panel (cs: Výsledek anonymizace).
 */

import { cs } from '../../i18n/cs.ts'
import {
  Badge,
  DataSurface,
  RaisedPanel,
  StatusChip,
} from '../../design-system/index.ts'
import type { StatusChipTone } from '../../components/ui/StatusChip.tsx'
import type { TextAnonymizationOutcome } from './textAnonymizationOutcome.ts'
import { useAppStore } from '../../app/store.ts'
import { getSessionModel } from '../workspace/sessionModel.ts'
import { buildTextAnonymizationOutcome } from './textAnonymizationOutcome.ts'
import { labelDisplayName } from '../import-log/textEncoding.ts'

function gateTone(gate: TextAnonymizationOutcome['gate']): StatusChipTone {
  if (gate === 'AI_READY') return 'ok'
  if (gate === 'AI_READY_WITH_GAPS') return 'warn'
  return 'error'
}

function gateBadgeTone(
  gate: TextAnonymizationOutcome['gate'],
): 'safe' | 'warn' | 'blocked' {
  if (gate === 'AI_READY') return 'safe'
  if (gate === 'AI_READY_WITH_GAPS') return 'warn'
  return 'blocked'
}

export function TextAnonymizationOutcomePanel({
  className,
  testId = 'text-anonymization-outcome-panel',
}: {
  readonly className?: string
  readonly testId?: string
} = {}) {
  const sessionEpoch = useAppStore((s) => s.sessionEpoch)
  const phase = useAppStore((s) => s.phase)
  const planBusy = useAppStore((s) => s.planBusy)
  const textSourceMeta = useAppStore((s) => s.textSourceMeta)
  const session = sessionEpoch >= 0 ? getSessionModel() : null

  if ((phase !== 'workspace' && phase !== 'correlation-review') || !session || planBusy) {
    return null
  }

  const outcome = buildTextAnonymizationOutcome({
    entities: session.entities,
    categoryMasters: session.categoryMasters,
    failedRuleIds: session.meta.failedRuleIds,
    incidents: session.incidents,
    oversizedLines: session.meta.oversizedLines,
  })

  return (
    <RaisedPanel
      className={['anonymization-outcome anonymization-outcome--text', className]
        .filter(Boolean)
        .join(' ')}
      data-testid={testId}
      data-gate={outcome.gate}
    >
      <header className="anonymization-outcome__head">
        <h2 className="anonymization-outcome__title type-section-title">
          {cs.pcap.outcome.textTitle}
        </h2>
        <span data-testid={`${testId}-gate`} data-gate={outcome.gate}>
          <Badge tone={gateBadgeTone(outcome.gate)}>
            <StatusChip tone={gateTone(outcome.gate)} label={outcome.gateLabel} compact />
            <span className="anonymization-outcome__gate-label">{outcome.gateLabel}</span>
          </Badge>
        </span>
      </header>

      <p
        className="anonymization-outcome__summary"
        role="status"
        aria-live="polite"
        data-testid={`${testId}-summary`}
      >
        {outcome.summarySentence}
      </p>

      {textSourceMeta ? (
        <p className="type-meta" data-testid={`${testId}-encoding`}>
          {cs.pcap.outcome.textEncoding(
            labelDisplayName(textSourceMeta.sourceEncoding),
            textSourceMeta.outputEncoding.toUpperCase(),
            textSourceMeta.structuredFormat && textSourceMeta.structuredFormat !== 'plain'
              ? textSourceMeta.structuredFormat
              : null,
          )}
        </p>
      ) : null}

      <DataSurface className="anonymization-outcome__table-wrap" data-testid={`${testId}-categories`}>
        <h3 className="type-meta">{cs.pcap.outcome.textCategories}</h3>
        {outcome.categories.length === 0 ? (
          <p className="type-meta">{cs.pcap.outcome.textNoFindings}</p>
        ) : (
          <table className="anonymization-outcome__table">
            <thead>
              <tr>
                <th scope="col">{cs.pcap.outcome.colCategory}</th>
                <th scope="col">{cs.pcap.outcome.colValues}</th>
                <th scope="col">{cs.pcap.outcome.colOccurrences}</th>
                <th scope="col">{cs.pcap.outcome.colReplaced}</th>
              </tr>
            </thead>
            <tbody>
              {outcome.categories.map((c) => (
                <tr key={c.category}>
                  <td>{c.label}</td>
                  <td>{c.uniqueCount}</td>
                  <td>{c.occurrenceCount}</td>
                  <td>{c.enabledUnique}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </DataSurface>

      {outcome.failedRuleIds.length > 0 ? (
        <p className="type-meta" data-testid={`${testId}-failed-rules`}>
          {cs.pcap.outcome.textFailedRules}: {outcome.failedRuleIds.join(', ')}
        </p>
      ) : null}

      {outcome.oversizedLines.length > 0 ? (
        <p className="type-meta" data-testid={`${testId}-long-lines`}>
          {cs.pcap.outcome.textLongLines}: {outcome.oversizedLines.slice(0, 20).join(', ')}
          {outcome.oversizedLines.length > 20
            ? ` ${cs.pcap.outcome.incidentsMore(outcome.oversizedLines.length - 20)}`
            : ''}
        </p>
      ) : null}

      <details className="anonymization-outcome__incidents" data-testid={`${testId}-incidents`}>
        <summary>
          {cs.pcap.outcome.incidentsTitle}
          {outcome.incidentTotal > 0 ? ` (${outcome.incidentTotal})` : ''}
        </summary>
        {outcome.incidents.length === 0 ? (
          <p className="type-meta">{cs.pcap.outcome.noIncidents}</p>
        ) : (
          <ul>
            {outcome.incidents.map((inc, i) => (
              <li key={`${inc.lineNumber ?? 'x'}-${i}`}>
                {inc.lineNumber != null ? `ř.${inc.lineNumber}` : '—'}
                {` — ${inc.reasonLabel} → ${inc.fallbackLabel}`}
              </li>
            ))}
            {outcome.incidentMoreCount > 0 ? (
              <li className="type-meta">{cs.pcap.outcome.incidentsMore(outcome.incidentMoreCount)}</li>
            ) : null}
          </ul>
        )}
      </details>
    </RaisedPanel>
  )
}
