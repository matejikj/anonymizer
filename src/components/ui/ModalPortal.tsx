import { createPortal } from 'react-dom'
import type { ReactNode } from 'react'

/** Render modals on `document.body` so `position: fixed` is not trapped by header `backdrop-filter`. */
export function ModalPortal({ children }: { children: ReactNode }) {
  if (typeof document === 'undefined') return null
  return createPortal(children, document.body)
}
