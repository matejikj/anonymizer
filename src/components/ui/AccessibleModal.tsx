import { useRef, type ReactNode } from 'react'
import { ModalPortal } from './ModalPortal.tsx'
import { useModalFocusTrap } from './useModalFocusTrap.ts'

export function AccessibleModal(props: {
  open: boolean
  onClose: () => void
  titleId: string
  title: string
  testId?: string
  /** Wider dialog for tables / dense content (e.g. anonymization outcome). */
  wide?: boolean
  /** Readable starting point for result dialogs with long tables. */
  focusTitle?: boolean
  children: ReactNode
  actions: ReactNode
}): React.ReactElement | null {
  const dialogRef = useRef<HTMLDivElement>(null)
  useModalFocusTrap({ open: props.open, onClose: props.onClose, dialogRef })

  if (!props.open) return null

  return (
    <ModalPortal>
      <div
        className="modal-backdrop"
        role="presentation"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) props.onClose()
        }}
      >
        <div
          ref={dialogRef}
          className={['modal', props.wide ? 'modal--wide' : ''].filter(Boolean).join(' ')}
          role="dialog"
          aria-modal="true"
          aria-labelledby={props.titleId}
          data-testid={props.testId}
        >
          <h2 id={props.titleId} tabIndex={props.focusTitle ? -1 : undefined} data-autofocus={props.focusTitle || undefined}>{props.title}</h2>
          {props.children}
          <div className="modal__actions">{props.actions}</div>
        </div>
      </div>
    </ModalPortal>
  )
}
