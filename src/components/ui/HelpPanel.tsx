import { useId, useRef, useState, type ReactNode } from 'react'
import { useAppStore } from '../../app/store.ts'
import { ModalPortal } from './ModalPortal.tsx'
import { useModalFocusTrap } from './useModalFocusTrap.ts'
import { IconButton } from '../../design-system/index.ts'
import { IconClose, IconHelp, IconInfo, IconWarning } from './icons.tsx'
import { cs } from '../../i18n/cs.ts'

type HelpTabId = 'start' | 'text' | 'pcap'

const TABS: readonly { id: HelpTabId; label: string }[] = [
  { id: 'start', label: cs.help.nav.start },
  { id: 'text', label: cs.help.nav.text },
  { id: 'pcap', label: cs.help.nav.pcap },
]

/**
 * In-app help — short beginner guide (AccessibleModal).
 */
export function HelpPanel() {
  const open = useAppStore((s) => s.helpOpen)
  const titleId = useId()
  const tablistId = useId()
  const dialogRef = useRef<HTMLElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)
  const [tab, setTab] = useState<HelpTabId>('start')

  const onClose = () => {
    const opener =
      document.activeElement instanceof HTMLElement &&
      document.activeElement.closest?.('[data-testid="help-open"]')
        ? document.activeElement
        : document.querySelector<HTMLElement>('[data-testid="help-open"]')
    useAppStore.getState().setHelpOpen(false)
    window.requestAnimationFrame(() => {
      opener?.focus({ preventScroll: true })
      window.setTimeout(() => {
        if (opener && document.activeElement !== opener) opener.focus({ preventScroll: true })
      }, 0)
    })
  }

  useModalFocusTrap({ open, onClose, dialogRef })

  if (!open) return null

  const activeLabel = TABS.find((t) => t.id === tab)?.label ?? cs.help.title

  return (
    <ModalPortal>
      <div
        className="modal-backdrop"
        role="presentation"
        data-testid="help-backdrop"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) onClose()
        }}
      >
        <article
          ref={dialogRef}
          className="modal modal--wide help-panel"
          role="dialog"
          aria-modal="true"
          aria-labelledby={titleId}
          id="help"
          data-testid="help-panel"
        >
          <header className="help-panel__header">
            <div className="help-panel__hero">
              <div className="help-panel__brand-row" aria-hidden="true">
                <span className="help-panel__glyph">
                  <IconHelp size={20} />
                </span>
                <span className="help-panel__redact">
                  <i />
                  <i />
                  <i />
                  <i />
                </span>
              </div>
              <p className="help-panel__eyebrow">{cs.help.eyebrow}</p>
              <h2 id={titleId} data-autofocus tabIndex={-1}>
                {cs.help.title}
              </h2>
              <p className="help-panel__tagline">{cs.help.tagline}</p>
              <ul className="help-panel__chips">
                {cs.help.chips.map((chip) => (
                  <li key={chip}>{chip}</li>
                ))}
              </ul>
            </div>
            <IconButton label={cs.help.close} data-testid="help-close" onClick={onClose}>
              <IconClose size={18} />
            </IconButton>
          </header>

          <div
            className="help-panel__tabs"
            role="tablist"
            id={tablistId}
            aria-label={cs.help.navLabel}
          >
            {TABS.map((item) => {
              const selected = item.id === tab
              return (
                <button
                  key={item.id}
                  type="button"
                  role="tab"
                  id={`help-tab-${item.id}`}
                  aria-selected={selected}
                  aria-controls={`help-panel-${item.id}`}
                  tabIndex={selected ? 0 : -1}
                  className={
                    selected ? 'help-panel__tab help-panel__tab--active' : 'help-panel__tab'
                  }
                  data-testid={`help-tab-${item.id}`}
                  onClick={() => setTab(item.id)}
                  onKeyDown={(event) => {
                    const idx = TABS.findIndex((t) => t.id === item.id)
                    if (event.key === 'ArrowRight') {
                      event.preventDefault()
                      const next = TABS[(idx + 1) % TABS.length]!
                      setTab(next.id)
                      document.getElementById(`help-tab-${next.id}`)?.focus()
                    } else if (event.key === 'ArrowLeft') {
                      event.preventDefault()
                      const prev = TABS[(idx - 1 + TABS.length) % TABS.length]!
                      setTab(prev.id)
                      document.getElementById(`help-tab-${prev.id}`)?.focus()
                    } else if (event.key === 'Home') {
                      event.preventDefault()
                      setTab(TABS[0]!.id)
                      document.getElementById(`help-tab-${TABS[0]!.id}`)?.focus()
                    } else if (event.key === 'End') {
                      event.preventDefault()
                      const last = TABS[TABS.length - 1]!
                      setTab(last.id)
                      document.getElementById(`help-tab-${last.id}`)?.focus()
                    }
                  }}
                >
                  {item.label}
                </button>
              )
            })}
          </div>

          <div
            ref={bodyRef}
            className="help-panel__body"
            tabIndex={0}
            role="tabpanel"
            id={`help-panel-${tab}`}
            aria-labelledby={`help-tab-${tab}`}
            aria-label={activeLabel}
            data-testid="help-panel-body"
          >
            {tab === 'start' ? <StartTab /> : null}
            {tab === 'text' ? <TextTab /> : null}
            {tab === 'pcap' ? <PcapTab /> : null}
          </div>
        </article>
      </div>
    </ModalPortal>
  )
}

function HelpSection({ title, children }: { readonly title: string; readonly children: ReactNode }) {
  return (
    <section className="help-panel__section">
      <h3>{title}</h3>
      {children}
    </section>
  )
}

function Steps({ items }: { readonly items: readonly string[] }) {
  return (
    <ol className="help-panel__steps">
      {items.map((step) => (
        <li key={step}>{step}</li>
      ))}
    </ol>
  )
}

function BulletList({ items }: { readonly items: readonly string[] }) {
  return (
    <ul className="help-panel__bullets">
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  )
}

function Aside({
  children,
  warn = false,
}: {
  readonly children: ReactNode
  readonly warn?: boolean
}) {
  return (
    <p className={warn ? 'help-panel__aside help-panel__aside--warn' : 'help-panel__aside'}>
      {warn ? <IconWarning size={16} /> : <IconInfo size={16} />}
      <span>{children}</span>
    </p>
  )
}

function StartTab() {
  return (
    <>
      <HelpSection title={cs.help.whatTitle}>
        <p className="help-panel__lede">{cs.help.whatBody}</p>
        <BulletList items={cs.help.whatItems} />
      </HelpSection>
      <HelpSection title={cs.help.startTitle}>
        <Steps items={cs.help.startSteps} />
        <Aside>{cs.help.startTip}</Aside>
      </HelpSection>
      <HelpSection title={cs.help.rememberTitle}>
        <BulletList items={cs.help.rememberItems} />
      </HelpSection>
    </>
  )
}

function TextTab() {
  return (
    <>
      <HelpSection title={cs.help.textTitle}>
        <p className="help-panel__lede">{cs.help.textBody}</p>
        <Steps items={cs.help.textSteps} />
        <Aside>{cs.help.textTip}</Aside>
      </HelpSection>
      <HelpSection title={cs.help.multiTitle}>
        <p className="help-panel__lede">{cs.help.multiBody}</p>
      </HelpSection>
    </>
  )
}

function PcapTab() {
  return (
    <>
      <HelpSection title={cs.help.pcapTitle}>
        <p className="help-panel__lede">{cs.help.pcapBody}</p>
        <BulletList items={cs.help.pcapItems} />
        <Aside>{cs.help.pcapTip}</Aside>
      </HelpSection>
      <HelpSection title={cs.help.pcapRecoveryTitle}>
        <p className="help-panel__lede">{cs.help.pcapRecoveryBody}</p>
        <Steps items={cs.help.pcapRecoverySteps} />
        <Aside warn>{cs.help.pcapRecoveryWarn}</Aside>
      </HelpSection>
    </>
  )
}
