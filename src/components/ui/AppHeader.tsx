import { cs } from '../../i18n/cs.ts'
import { DetectionSettingsPopover } from './DetectionSettingsPopover.tsx'
import { IconBook, IconHelp, IconLock } from './icons.tsx'
import { SessionStepper } from './SessionStepper.tsx'
import { ThemeToggle } from './ThemeToggle.tsx'
import { Button } from '../../design-system/Button.tsx'
import { useAppStore } from '../../app/store.ts'
import { BYTES_PER_MIB, MAX_TEXT_FILE_BYTES, MAX_PCAP_FILE_BYTES, TEXT_INPUT_LIMITS, CORRELATION_SESSION_LIMITS } from '../../domain/capabilityContract.ts'

const uploadLimits = cs.header.uploadLimits(
  MAX_TEXT_FILE_BYTES / BYTES_PER_MIB,
  TEXT_INPUT_LIMITS.fileMaxLines,
  MAX_PCAP_FILE_BYTES / BYTES_PER_MIB,
  CORRELATION_SESSION_LIMITS.maxSources,
  CORRELATION_SESSION_LIMITS.maxAggregateBytes / BYTES_PER_MIB,
)

/**
 * Stable glass chrome — upload limits, trust badge, stepper, utilities (Stage 8.3).
 * Privacy is an icon + accessible label (Forensic Bench), not a text pill.
 */
export function AppHeader() {
  const helpOpen = useAppStore((s) => s.helpOpen)
  const docsOpen = useAppStore((s) => s.docsOpen)

  return (
    <header className="app-header" data-testid="app-header">
      <div className="app-header__brand">
        <a className="app-header__name app-header__limits" href="#main" title={`${uploadLimits}\n${cs.header.uploadLimitsHint}`}>
          {uploadLimits}
        </a>
        <span className="app-header__privacy" role="status" data-testid="app-privacy-badge" title={cs.privacyBadge}>
          <IconLock size={16} />
          <span className="visually-hidden">{cs.privacyBadge}</span>
        </span>
      </div>
      <SessionStepper />
      <nav className="app-header__nav" aria-label={cs.a11y.mainNav}>
        <DetectionSettingsPopover />
        <ThemeToggle />
        <Button
          variant="ghost"
          className="app-header__utility"
          data-testid="docs-open"
          aria-expanded={docsOpen}
          aria-controls={docsOpen ? 'anonymization-docs' : undefined}
          aria-haspopup="dialog"
          onClick={() => useAppStore.getState().setDocsOpen(true)}
        >
          <IconBook size={18} />
          <span>{cs.header.docs}</span>
        </Button>
        <Button
          variant="ghost"
          className="app-header__utility"
          data-testid="help-open"
          aria-expanded={helpOpen}
          aria-controls={helpOpen ? 'help' : undefined}
          aria-haspopup="dialog"
          onClick={() => useAppStore.getState().setHelpOpen(true)}
        >
          <IconHelp size={18} />
          <span>{cs.header.help}</span>
        </Button>
      </nav>
    </header>
  )
}
