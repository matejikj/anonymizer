import type { ReactNode } from 'react'
import { cs } from '../../i18n/cs.ts'
import { StatusGlyph, type StatusGlyphKind } from '../../design-system/index.ts'

export interface PcapVerdictDetailsProps {
  readonly primaryVerdict: string
  readonly reasons: readonly string[]
  readonly glyphKind: StatusGlyphKind
  readonly className?: string
  readonly testId?: string
  readonly children?: ReactNode
}

/**
 * Compact PCAP security verdict — one-line summary, reasons and extras in <details>.
 */
export function PcapVerdictDetails({
  primaryVerdict,
  reasons,
  glyphKind,
  className,
  testId,
  children,
}: PcapVerdictDetailsProps) {
  const hasBody = reasons.length > 0 || children != null

  return (
    <details
      className={['pcap-verdict-details', className].filter(Boolean).join(' ')}
      data-testid={testId}
    >
      <summary className="pcap-verdict-details__summary">
        <StatusGlyph kind={glyphKind} className="pcap-verdict-details__icon" />
        <span className="pcap-verdict-details__headline">{primaryVerdict}</span>
        {hasBody ? (
          <span className="pcap-verdict-details__toggle">{cs.pcap.coverageUx.verdictDetailsToggle}</span>
        ) : null}
      </summary>
      {hasBody ? (
        <div className="pcap-verdict-details__body">
          {reasons.length > 0 ? (
            <ul className="pcap-verdict-details__reasons">
              {reasons.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          ) : null}
          {children}
        </div>
      ) : null}
    </details>
  )
}
