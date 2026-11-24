import { useRef, type ReactNode } from 'react'
import { ModalPortal } from './ModalPortal.tsx'
import { useModalFocusTrap } from './useModalFocusTrap.ts'
import { cs } from '../../i18n/cs.ts'
import { IconButton } from '../../design-system/IconButton.tsx'
import { IconClose } from './icons.tsx'

export function AccessibleDrawer(props: {
  open: boolean
  onClose: () => void
  titleId: string
  title: string
  testId?: string
  children: ReactNode
  footer: ReactNode
}): React.ReactElement | null {
  const panelRef = useRef<HTMLDivElement>(null)
  useModalFocusTrap({ open: props.open, onClose: props.onClose, dialogRef: panelRef })

  if (!props.open) return null

  return (
    <ModalPortal>
      <div
        className="drawer-backdrop"
        role="presentation"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) props.onClose()
        }}
      >
        <aside
          ref={panelRef}
          className="drawer"
          role="dialog"
          aria-modal="true"
          aria-labelledby={props.titleId}
          data-testid={props.testId}
        >
          <header className="drawer__header">
            <h2 id={props.titleId}>{props.title}</h2>
            <IconButton tiny label={cs.drawer.close} className="drawer__close" onClick={props.onClose}>
              <IconClose size={16} />
            </IconButton>
          </header>
          <div className="drawer__body">{props.children}</div>
          <footer className="drawer__footer">{props.footer}</footer>
        </aside>
      </div>
    </ModalPortal>
  )
}
