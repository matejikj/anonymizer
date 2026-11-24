/**
 * T10 / T67 — „Výsledek anonymizace“ panel (PCAP).
 * Design-system only; states via StatusChip / Badge; no hardcoded colors.
 * AI_READY_WITH_GAPS is informational green — never a review call to action.
 */

import { cs } from '../../i18n/cs.ts'
import {
  Badge,
  Button,
  RaisedPanel,
  StatusChip,
} from '../../design-system/index.ts'
import type { AnonymizationOutcome, OutcomeFamilyState } from '../coverage/anonymizationOutcome.ts'
import type { StatusChipTone } from '../../components/ui/StatusChip.tsx'
import { usePcapStore } from './pcapStore.ts'
import { refreshPcapFilter } from './pcapLoadController.ts'
import { DEFAULT_PCAP_FILTER } from './pcapSession.ts'

export interface AnonymizationOutcomePanelProps {
  readonly outcome: AnonymizationOutcome
  readonly className?: string
  readonly testId?: string
  /** When false, hide „Zobrazit pakety“ (e.g. correlation completion). */
  readonly showPacketActions?: boolean
  readonly announceLive?: boolean
  /** Hide the panel h2 when the host dialog already provides the title. */
  readonly hideTitle?: boolean
  /** Called after „Zobrazit pakety“ applies the filter (e.g. close outcome dialog). */
  readonly onAfterShowPackets?: () => void
}

function gateTone(gate: AnonymizationOutcome['gate']): StatusChipTone {
  // T67 — gaps are green informational, not amber “needs review”.
  if (gate === 'AI_READY' || gate === 'AI_READY_WITH_GAPS') return 'ok'
  return 'ok'
}

function gateBadgeTone(
  gate: AnonymizationOutcome['gate'],
): 'safe' | 'warn' | 'blocked' {
  if (gate === 'AI_READY' || gate === 'AI_READY_WITH_GAPS') return 'safe'
  return 'safe'
}

function stateTone(state: OutcomeFamilyState): StatusChipTone {
  switch (state) {
    case 'anonymized':
      return 'ok'
    case 'encrypted-kept':
      return 'active'
    case 'anonymized-with-loss':
      return 'ok'
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
  const setDisplayFilterDraft = usePcapStore((s) => s.setDisplayFilterDraft)
  const applyDisplayFilter = usePcapStore((s) => s.applyDisplayFilter)

  const limitedCount = outcome.families.filter((f) => f.state === 'anonymized-with-loss').length
  const processedCount = outcome.families.length - limitedCount

  const showPackets = (familyId: string) => {
    // Navigate to the whole family, including disjoint protocols such as RTP and RTCP.
    // Use the visible filter so the user can edit or clear this selection.
    const expression = `protocol.family == ${JSON.stringify(familyId)}`
    setFilter({ ...DEFAULT_PCAP_FILTER })
    setDisplayFilterDraft(expression, 'valid', null)
    applyDisplayFilter(expression)
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
      tabIndex={hideTitle ? 0 : undefined}
      aria-label={hideTitle ? cs.pcap.outcome.title : undefined}
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

      <section className="anonymization-outcome__decision" data-gate={outcome.gate}>
        <h3>{cs.pcap.outcome.decisionTitle[outcome.gate]}</h3>
        <p
          className="anonymization-outcome__summary"
          data-testid={`${testId}-summary`}
          {...(announceLive ? { role: 'status', 'aria-live': 'polite' as const } : {})}
        >
          {outcome.summarySentence}
        </p>
        <dl className="anonymization-outcome__counts">
          {([[cs.pcap.outcome.processedCount, processedCount], [cs.pcap.outcome.limitedCount, limitedCount]] as const).map(([label, count]) => (
            <div key={label}><dt>{label}</dt><dd>{count}</dd></div>
          ))}
        </dl>
      </section>

      <div className="anonymization-outcome__families" data-testid={`${testId}-families`}>
        {outcome.families.map(row => (
          <section
            key={row.familyId}
            className="anonymization-outcome__family"
            data-testid={`${testId}-family-${row.familyId}`}
            data-family-state={row.state}
            aria-labelledby={`${testId}-family-title-${row.familyId}`}
          >
            <header className="anonymization-outcome__family-head">
              <div className="anonymization-outcome__family-name">
                <h3 id={`${testId}-family-title-${row.familyId}`}>{row.familyLabel}</h3>
                <span className="type-meta" data-testid={`${testId}-count-${row.familyId}`}>{cs.pcap.outcome.packetCount(row.packetCount)}</span>
              </div>
              <StatusChip tone={stateTone(row.state)} label={row.stateLabel} />
              {showPacketActions && row.filterProtocol ? (
                <Button variant="ghost" data-testid={`${testId}-show-${row.familyId}`} onClick={() => showPackets(row.familyId)}>
                  {cs.pcap.outcome.showPackets}
                </Button>
              ) : null}
            </header>
            {row.probable ? <p className="anonymization-outcome__probable">{cs.pcap.outcome.probableNote}</p> : null}
            <ul className="anonymization-outcome__protocols">
              {row.protocols.map(protocol => (
                <li key={protocol.id} data-testid={`${testId}-protocol-${row.familyId}-${protocol.id}`} data-protocol-state={protocol.state}>
                  <div className="anonymization-outcome__protocol-head">
                    <h4>{protocol.label}</h4>
                    <span className="type-meta">{cs.pcap.outcome.protocolStatus[protocol.state]}</span>
                  </div>
                  <p><strong>{cs.pcap.outcome.methodLabel}: </strong>{protocol.method}</p>
                  <p className="anonymization-outcome__check"><strong>{cs.pcap.outcome.checkLabel}: </strong>{protocol.check}</p>
                </li>
              ))}
            </ul>
            <p className="anonymization-outcome__recommend">{row.recommendation}</p>
          </section>
        ))}
      </div>
      <p className="anonymization-outcome__note type-meta">{cs.pcap.outcome.familyOverlap}</p>
      <p className="anonymization-outcome__note type-meta" data-testid={`${testId}-assurance`}>{outcome.assuranceNote}</p>

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
