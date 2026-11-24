import { cs } from '../../i18n/cs.ts'
import { DetectionSettingsPopover } from './DetectionSettingsPopover.tsx'
import { IconBook, IconHelp, IconLock } from './icons.tsx'
import { SessionStepper } from './SessionStepper.tsx'
import { ThemeToggle } from './ThemeToggle.tsx'
import { IconButton } from '../../design-system/IconButton.tsx'
import { useAppStore } from '../../app/store.ts'

/**
 * Stable glass chrome — brand, trust badge, stepper, utilities (Stage 8.3).
 * Brand switches full ↔ compact via shell density without layout breakup.
 * Privacy is an icon + accessible label (Forensic Bench), not a text pill.
 */
export function AppHeader() {
  const helpOpen = useAppStore((s) => s.helpOpen)
  const docsOpen = useAppStore((s) => s.docsOpen)

  return (
    <header className="app-header" data-testid="app-header">
      <div className="app-header__brand">
        <a className="app-header__name" href="#main" title={cs.privacyBadge}>
          <span className="app-header__name-full">{cs.appName}</span>
          <span className="app-header__name-compact" aria-hidden="true">
            {cs.appNameCompact}
          </span>
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
        <IconButton
          label={cs.header.docs}
          data-testid="docs-open"
          aria-expanded={docsOpen}
          onClick={() => useAppStore.getState().setDocsOpen(true)}
        >
          <IconBook size={18} />
        </IconButton>
        <IconButton
          label={cs.header.help}
          data-testid="help-open"
          aria-expanded={helpOpen}
          onClick={() => useAppStore.getState().setHelpOpen(true)}
        >
          <IconHelp size={18} />
        </IconButton>
      </nav>
    </header>
  )
}
