import { cs } from '../../i18n/cs.ts'
import { getPcapCoverageViewModel } from './getPcapCoverageViewModel.ts'
import { usePcapStore } from './pcapStore.ts'
import { StatusGlyph } from '../../design-system/StatusGlyph.tsx'
import { IconButton } from '../../design-system/index.ts'
import { IconInfo } from '../../components/ui/icons.tsx'

export interface PcapStatusStripProps {
  readonly compact?: boolean
}

/**
 * Status strip — labels and verdict come from PcapCoverageViewModel (Stage 6 / 9).
 */
export function PcapStatusStrip({ compact = false }: PcapStatusStripProps) {
  const epoch = usePcapStore((s) => s.sessionEpoch)
  void epoch
  const vm = getPcapCoverageViewModel()
  if (!vm) return null

  const { summary } = vm
  const anonClass = summary.anonymization
  const integClass = summary.integrity
  const compatClass = summary.compatibility

  return (
    <div
      className={compact ? 'pcap-status-strip pcap-status-strip--compact' : 'pcap-status-strip'}
      role="group"
      aria-label={cs.pcap.status.groupLabel}
      data-testid="pcap-status-strip"
      data-plan-revision={vm.planRevision}
    >
      <IconButton
        className="pcap-status-strip__info"
        tiny
        label={cs.pcap.status.statusDisclaimer}
        data-testid="pcap-status-disclaimer"
      >
        <IconInfo size={16} />
      </IconButton>
      <details className={`pcap-status pcap-status--${anonClass}${compact ? ' pcap-status--compact' : ''}`}>
        <summary>
          <StatusGlyph
            kind={anonClass === 'covered' ? 'ok' : anonClass === 'exposed' ? 'warn' : 'blocked'}
            className="pcap-status__icon"
          />
          <span className="pcap-status__name">{cs.pcap.status.anonymization}</span>
          <span className="pcap-status__value">{summary.anonymizationLabel}</span>
        </summary>
        <p>{cs.pcap.status.anonHelp}</p>
        <ul>
          <li>{cs.pcap.status.changedCount.replace('{n}', String(summary.changedCount))}</li>
          <li>
            {cs.pcap.status.truncatedCount.replace('{n}', String(summary.removedCount))}
          </li>
          <li>{cs.pcap.status.unsupportedCount.replace('{n}', String(summary.attentionCount))}</li>
        </ul>
      </details>
      <details className={`pcap-status pcap-status--${integClass}${compact ? ' pcap-status--compact' : ''}`}>
        <summary>
          <StatusGlyph kind={integClass === 'ok' ? 'ok' : 'unknown'} className="pcap-status__icon" />
          <span className="pcap-status__name">{cs.pcap.status.integrity}</span>
          <span className="pcap-status__value">{summary.integrityLabel}</span>
        </summary>
        <p>{cs.pcap.status.integHelp}</p>
      </details>
      <details className={`pcap-status pcap-status--${compatClass}${compact ? ' pcap-status--compact' : ''}`}>
        <summary>
          <StatusGlyph kind={compatClass === 'blocked' ? 'blocked' : 'ok'} className="pcap-status__icon" />
          <span className="pcap-status__name">{cs.pcap.status.compatibility}</span>
          <span className="pcap-status__value">{summary.compatibilityLabel}</span>
        </summary>
        <p>{cs.pcap.status.compatHelp}</p>
      </details>
    </div>
  )
}
