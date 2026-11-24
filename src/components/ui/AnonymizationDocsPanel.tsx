import { useId, useMemo, useRef } from 'react'
import { useAppStore } from '../../app/store.ts'
import { ModalPortal } from './ModalPortal.tsx'
import { useModalFocusTrap } from './useModalFocusTrap.ts'
import { IconButton } from '../../design-system/index.ts'
import { IconBook, IconClose } from './icons.tsx'
import { cs } from '../../i18n/cs.ts'
import { renderMarkdownLite } from './markdownLite.tsx'
import anonymizationDocsRaw from '../../../docs/PCAP_ANONYMIZATION_OVERVIEW.md?raw'

/** Bundled explanation of the anonymization pipeline, grouped into readable chapters. */
export function AnonymizationDocsPanel() {
  const open = useAppStore((s) => s.docsOpen)
  const titleId = useId()
  const dialogRef = useRef<HTMLElement>(null)
  const content = useMemo(() => {
    const [intro = '', ...sections] = anonymizationDocsRaw.split(/^## /m)
    return {
      intro: renderMarkdownLite(intro.replace(/^# .*\n/, '')),
      sections: sections.map((section) => {
        const lineEnd = section.indexOf('\n')
        return { title: section.slice(0, lineEnd), body: section.slice(lineEnd + 1) }
      }),
    }
  }, [])

  const onClose = () => {
    const opener =
      document.activeElement instanceof HTMLElement &&
      document.activeElement.closest?.('[data-testid="docs-open"]')
        ? document.activeElement
        : document.querySelector<HTMLElement>('[data-testid="docs-open"]')
    useAppStore.getState().setDocsOpen(false)
    window.requestAnimationFrame(() => {
      opener?.focus({ preventScroll: true })
      window.setTimeout(() => {
        if (opener && document.activeElement !== opener) opener.focus({ preventScroll: true })
      }, 0)
    })
  }

  useModalFocusTrap({ open, onClose, dialogRef })

  if (!open) return null

  return (
    <ModalPortal>
      <div
        className="modal-backdrop"
        role="presentation"
        data-testid="docs-backdrop"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) onClose()
        }}
      >
        <article
          ref={dialogRef}
          className="modal modal--wide docs-panel"
          role="dialog"
          aria-modal="true"
          aria-labelledby={titleId}
          id="anonymization-docs"
          data-testid="docs-panel"
        >
          <header className="docs-panel__header">
            <div className="docs-panel__hero">
              <div className="docs-panel__brand-row" aria-hidden="true">
                <span className="docs-panel__glyph">
                  <IconBook size={20} />
                </span>
              </div>
              <p className="docs-panel__eyebrow">{cs.docsPanel.eyebrow}</p>
              <h2 id={titleId} data-autofocus tabIndex={-1}>
                {cs.docsPanel.title}
              </h2>
              <p className="docs-panel__tagline">{cs.docsPanel.tagline}</p>
            </div>
            <IconButton label={cs.docsPanel.close} data-testid="docs-close" onClick={onClose}>
              <IconClose size={18} />
            </IconButton>
          </header>

          <div className="docs-panel__body" tabIndex={0} data-testid="docs-panel-body">
            <ol className="docs-panel__flow" aria-label={cs.docsPanel.flowLabel}>
              {cs.docsPanel.flow.map((step, index) => (
                <li key={step}><span aria-hidden="true">{index + 1}</span>{step}</li>
              ))}
            </ol>
            <div className="docs-panel__intro">{content.intro}</div>
            <p className="docs-panel__section-label">{cs.docsPanel.readMore}</p>
            {content.sections.map((section, index) => (
              <details className="docs-panel__section" key={section.title} open={index === 0 ? true : undefined}>
                <summary tabIndex={0}><span className="docs-panel__section-number" aria-hidden="true">{index + 1}</span>{section.title}</summary>
                <div className="docs-panel__section-content">
                  {renderMarkdownLite(section.body)}
                </div>
              </details>
            ))}
          </div>
        </article>
      </div>
    </ModalPortal>
  )
}
