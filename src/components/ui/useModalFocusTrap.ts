import { useEffect, useRef, type RefObject } from 'react'

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function useModalFocusTrap(options: {
  open: boolean
  onClose: () => void
  dialogRef: RefObject<HTMLElement | null>
}): void {
  const { open, onClose, dialogRef } = options
  const triggerRef = useRef<HTMLElement | null>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    if (!open) return

    triggerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null

    const dialog = dialogRef.current
    if (!dialog) return

    const focusables = () =>
      Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (el) => !el.hasAttribute('disabled') && el.offsetParent !== null,
      )

    const focusFirst = () => {
      const list = focusables()
      const preferred = dialog.querySelector<HTMLElement>('[data-autofocus]')
      ;(preferred ?? list[0])?.focus()
    }

    const timer = window.setTimeout(focusFirst, 0)

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        event.stopPropagation()
        onCloseRef.current()
        return
      }
      if (event.key !== 'Tab') return
      const list = focusables()
      if (list.length === 0) return
      const first = list[0]!
      const last = list[list.length - 1]!
      const active = document.activeElement
      // Initial focus may be a heading with tabindex=-1, before all tab stops.
      const onTabStop = list.some((element) => element === active)
      if (event.shiftKey && (active === first || !onTabStop)) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && (active === last || !dialog.contains(active))) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown, true)
    return () => {
      window.clearTimeout(timer)
      document.removeEventListener('keydown', onKeyDown, true)
      const trigger = triggerRef.current
      if (trigger && document.contains(trigger) && document.activeElement !== trigger) {
        window.setTimeout(() => trigger.focus({ preventScroll: true }), 0)
      }
    }
  }, [open, dialogRef])
}
