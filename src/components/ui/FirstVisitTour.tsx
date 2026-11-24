import { useEffect, useId, useRef, useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import { isOnboardingComplete, markOnboardingComplete } from '../../app/onboardingModel.ts'
import { useAppStore } from '../../app/store.ts'
import { useModalFocusTrap } from './useModalFocusTrap.ts'
import { Button } from '../../design-system/Button.tsx'

const STEPS = ['dropzone', 'multi', 'export'] as const
type TourStep = (typeof STEPS)[number]

const ANCHOR_TEST_ID: Record<TourStep, string> = {
  dropzone: 'multi-source-dropzone',
  multi: 'multi-source-dropzone',
  export: 'empty-resolve-return',
}

/**
 * Anchored glass onboarding popover (Stage 8.3) — focus trap, Escape, no CTA cover.
 */
export function FirstVisitTour() {
  const phase = useAppStore((s) => s.phase)
  const [visible, setVisible] = useState(false)
  const [stepIndex, setStepIndex] = useState(0)
  const dialogRef = useRef<HTMLDivElement>(null)
  const titleId = useId()
  const bodyId = useId()

  useEffect(() => {
    if (phase !== 'empty' || isOnboardingComplete()) {
      setVisible(false)
      return
    }
    const timer = window.setTimeout(() => setVisible(true), 400)
    return () => window.clearTimeout(timer)
  }, [phase])

  const dismiss = () => {
    markOnboardingComplete()
    setVisible(false)
  }

  useModalFocusTrap({ open: visible, onClose: dismiss, dialogRef })

  if (!visible) return null

  const step = STEPS[stepIndex]!
  const anchor = document.querySelector<HTMLElement>(`[data-testid="${ANCHOR_TEST_ID[step]}"]`)
  const rect = anchor?.getBoundingClientRect()

  let top = rect ? rect.bottom + 12 : 96
  let left = rect ? Math.max(16, rect.left) : 16
  top = Math.min(window.innerHeight - 200, top)
  left = Math.min(window.innerWidth - 320, left)

  const next = () => {
    if (stepIndex >= STEPS.length - 1) {
      dismiss()
      return
    }
    setStepIndex(stepIndex + 1)
  }

  return (
    <>
      <div className="first-visit-tour__scrim" aria-hidden="true" />
      <div
        ref={dialogRef}
        className="first-visit-tour ds-glass-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={bodyId}
        data-testid="first-visit-tour"
        style={{ top: `${top}px`, left: `${left}px` }}
      >
        <p className="first-visit-tour__step type-label">
          {cs.onboarding.stepCounter(stepIndex + 1, STEPS.length)}
        </p>
        <h2 id={titleId} className="first-visit-tour__title" data-autofocus tabIndex={-1}>
          {cs.onboarding.steps[step].title}
        </h2>
        <p id={bodyId} className="first-visit-tour__body">
          {cs.onboarding.steps[step].body}
        </p>
        <div className="first-visit-tour__actions">
          <Button variant="ghost" data-testid="first-visit-tour-dismiss" onClick={dismiss}>
            {cs.onboarding.dismiss}
          </Button>
          <Button variant="primary" data-testid="first-visit-tour-next" onClick={next}>
            {stepIndex >= STEPS.length - 1 ? cs.onboarding.done : cs.onboarding.next}
          </Button>
        </div>
      </div>
    </>
  )
}
