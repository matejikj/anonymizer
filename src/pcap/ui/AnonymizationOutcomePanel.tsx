/**
 * T10 — anonymization outcome panel (PCAP; cs: Výsledek anonymizace).
 * Design-system only; states via StatusChip / Badge; no hardcoded colors.
 */

import { cs } from '../../i18n/cs.ts'
import {
  Badge,
  Button,
  DataSurface,
  RaisedPanel,
  StatusChip,
} from '../../design-system/index.ts'
import type { AnonymizationOutcome, OutcomeFamilyState } from '../coverage/anonymizationOutcome.ts'
import type { StatusChipTone } from '../../components/ui/StatusChip.tsx'
import { usePcapStore } from './pcapStore.ts'
import { refreshPcapFilter } from './pcapLoadController.ts'

export interface AnonymizationOutcomePanelProps {
  readonly outcome: AnonymizationOutcome
  readonly className?: string
  readonly testId?: string
  /** When false, hide "Show packets" action (cs: Zobrazit pakety; e.g. correlation completion). */
  readonly showPacketActions?: boolean
  readonly announceLive?: boolean
  /** Hide the panel h2 when the host dialog already provides the title. */
  readonly hideTitle?: boolean
  /** Called after "Show packets" applies the filter (e.g. close outcome dialog). */
  readonly onAfterShowPackets?: () => void
}

function gateTone(gate: AnonymizationOutcome['gate']): StatusChipTone {
  if (gate === 'AI_READY') return 'ok'
  if (gate === 'AI_READY_WITH_GAPS') return 'warn'
  return 'error'
}

function gateBadgeTone(
  gate: AnonymizationOutcome['gate'],
): 'safe' | 'warn' | 'blocked' {
  if (gate === 'AI_READY') return 'safe'
  if (gate === 'AI_READY_WITH_GAPS') return 'warn'
  return 'blocked'
}

function stateTone(state: OutcomeFamilyState): StatusChipTone {
  switch (state) {
    case 'anonymized':
      return 'ok'
    case 'encrypted-kept':
      return 'active'
    case 'masked-without-analysis':
      return 'warn'
    case 'processing-failed':
      return 'error'
    case 'needs-attention':
      return 'error'
    default:
      return 'waiting'
  }
}

export function AnonymizationOutcomePanel({
  outcome,
  className,
  testId = 'anonymization-outcome-panel',
  showPacketActions = true,
  announceLive = true,
  hideTitle = false,
  onAfterShowPackets,
}: AnonymizationOutcomePanelProps) {
  const setFilter = usePcapStore((s) => s.setFilter)

  const showPackets = (protocol: string | null) => {
    if (!protocol) return
    setFilter({ protocol })
    queueMicrotask(() => refreshPcapFilter())
    onAfterShowPackets?.()
  }

  return (
    <RaisedPanel
      className={['anonymization-outcome', hideTitle ? 'anonymization-outcome--embedded' : '', className]
        .filter(Boolean)
        .join(' ')}
      data-testid={testId}
      data-gate={outcome.gate}
    >
      <header className="anonymization-outcome__head">
        {hideTitle ? null : (
          <h2 className="anonymization-outcome__title type-section-title">{cs.pcap.outcome.title}</h2>
        )}
        <span data-testid={`${testId}-gate`} data-gate={outcome.gate}>
          <Badge tone={gateBadgeTone(outcome.gate)}>
            <StatusChip tone={gateTone(outcome.gate)} label={outcome.gateLabel} compact />
            <span className="anonymization-outcome__gate-label">{outcome.gateLabel}</span>
          </Badge>
        </span>
      </header>

      <p
        className="anonymization-outcome__summary"
        data-testid={`${testId}-summary`}
        {...(announceLive
          ? { role: 'status', 'aria-live': 'polite' as const }
          : {})}
      >
        {outcome.summarySentence}
      </p>
      {announceLive ? (
        <span className="visually-hidden" role="status" aria-live="polite">
          {cs.pcap.outcome.liveAnnounce}
        </span>
      ) : null}

      <DataSurface className="anonymization-outcome__table-wrap" data-testid={`${testId}-families`}>
        <table className="anonymization-outcome__table">
          <thead>
            <tr>
              <th scope="col">{cs.pcap.outcome.colFamily}</th>
              <th scope="col">{cs.pcap.outcome.colState}</th>
              <th scope="col">{cs.pcap.outcome.colPackets}</th>
              <th scope="col">{cs.pcap.outcome.colRecommend}</th>
              {showPacketActions ? (
                <th scope="col">
                  <span className="visually-hidden">{cs.pcap.outcome.colActions}</span>
                </th>
              ) : null}
            </tr>
          </thead>
          <tbody>
            {outcome.families.map((row) => (
              <tr
                key={row.familyId}
                data-testid={`${testId}-family-${row.familyId}`}
                data-family-state={row.state}
              >
                <td>
                  {row.familyLabel}
                  {row.probable ? (
                    <span className="anonymization-outcome__probable"> {cs.pcap.outcome.probableNote}</span>
                  ) : null}
                </td>
                <td>
                  <StatusChip tone={stateTone(row.state)} label={row.stateLabel} />
                </td>
                <td>{row.packetCount}</td>
                <td>
                  <span className="anonymization-outcome__explain">{row.explanation}</span>
                  <span className="anonymization-outcome__recommend">{row.recommendation}</span>
                </td>
                {showPacketActions ? (
                  <td>
                    {row.filterProtocol ? (
                      <Button
                        variant="ghost"
                        data-testid={`${testId}-show-${row.familyId}`}
                        onClick={() => showPackets(row.filterProtocol)}
                      >
                        {cs.pcap.outcome.showPackets}
                      </Button>
                    ) : null}
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      </DataSurface>

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
              <li key={`${inc.packetNumber ?? inc.lineNumber ?? 'x'}-${i}`}>
                {inc.packetNumber != null ? `#${inc.packetNumber}` : null}
                {inc.lineNumber != null ? ` ř.${inc.lineNumber}` : null}
                {inc.protocol ? ` · ${inc.protocol}` : null}
                {` — ${inc.reasonLabel} → ${inc.fallbackLabel}`}
              </li>
            ))}
            {outcome.incidentMoreCount > 0 ? (
              <li className="type-meta">{cs.pcap.outcome.incidentsMore(outcome.incidentMoreCount)}</li>
            ) : null}
          </ul>
        )}
      </details>

      {outcome.maskedPacketRanges.length > 0 ? (
        <p className="anonymization-outcome__masked type-meta" data-testid={`${testId}-masked`}>
          {cs.pcap.outcome.maskedPackets}: {outcome.maskedPacketRanges.join(', ')}
        </p>
      ) : null}

      {outcome.supportRequests.length > 0 ? (
        <section
          className="anonymization-outcome__support"
          data-testid={`${testId}-support-requests`}
        >
          <h3 className="type-meta">{cs.pcap.outcome.supportTitle}</h3>
          <ul className="anonymization-outcome__support-list">
            {outcome.supportRequests.map((req) => (
              <li key={req.code} data-testid={`${testId}-support-${req.code}`}>
                <p className="anonymization-outcome__support-msg">{req.message}</p>
                <Button
                  variant="ghost"
                  data-testid={`${testId}-copy-support-${req.code}`}
                  onClick={() => {
                    void navigator.clipboard?.writeText(req.clipboardText)
                  }}
                >
                  {cs.pcap.outcome.copySupportRequest}
                </Button>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <p className="anonymization-outcome__impact type-meta" data-testid={`${testId}-impact`}>
        {cs.pcap.outcome.impactLine(
          outcome.diagnosticImpact.analyzableFamilyCount,
          outcome.diagnosticImpact.maskedWithoutAnalysisFamilyCount,
          outcome.diagnosticImpact.needsAttentionFamilyCount,
          outcome.diagnosticImpact.processingFailedPacketCount,
        )}
      </p>
    </RaisedPanel>
  )
}
