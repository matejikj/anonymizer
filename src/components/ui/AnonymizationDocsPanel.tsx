import { useId, useMemo, useRef } from 'react'
import { useAppStore } from '../../app/store.ts'
import { ModalPortal } from './ModalPortal.tsx'
import { useModalFocusTrap } from './useModalFocusTrap.ts'
import { IconButton } from '../../design-system/index.ts'
import { IconBook, IconClose } from './icons.tsx'
import { cs } from '../../i18n/cs.ts'
import { renderMarkdownLite } from './markdownLite.tsx'
import anonymizationDocsRaw from '../../i18n/anonymizationDocs.cs.md?raw'
import {
  buildProtocolSupportMatrix,
  injectProtocolMatrixMarkdown,
  renderProtocolSupportMatrixMarkdown,
} from '../../pcap/docs/protocolSupportMatrix.ts'

/**
 * "Jak anonymizujeme?" — read-only technical explainer for Czech customers.
 * Content lives in `src/i18n/anonymizationDocs.cs.md` (UI copy, not construction docs).
 * Bundled at build time (no runtime fetch — CSP `connect-src 'none'`); same modal
 * chrome/focus-trap pattern as HelpPanel, but a single scrollable document instead of tabs.
 */
export function AnonymizationDocsPanel() {
  const open = useAppStore((s) => s.docsOpen)
  const titleId = useId()
  const dialogRef = useRef<HTMLElement>(null)

  // T32 — inject live matrix from the same module as `npm run docs:protocol-matrix`.
  const content = useMemo(() => {
    const matrixMd = renderProtocolSupportMatrixMarkdown(buildProtocolSupportMatrix())
    const body =
      injectProtocolMatrixMarkdown(anonymizationDocsRaw, matrixMd) ?? anonymizationDocsRaw
    return renderMarkdownLite(body)
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
            {content}
          </div>
        </article>
      </div>
    </ModalPortal>
  )
}
