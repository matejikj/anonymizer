import { AccessibleModal, Button } from '../../design-system/index.ts'
import { useAppStore } from '../../app/store.ts'
import { cs } from '../../i18n/cs.ts'
import { getSessionModel } from '../workspace/sessionModel.ts'
import { TextAnonymizationOutcomePanel } from './TextAnonymizationOutcomePanel.tsx'

/** Text results share the PCAP dialog workflow, leaving the editors unobstructed. */
export function TextOutcomeDialog() {
  const open = useAppStore((s) => s.textOutcomeDialogOpen)
  const phase = useAppStore((s) => s.phase)
  const busy = useAppStore((s) => s.planBusy)
  const sessionEpoch = useAppStore((s) => s.sessionEpoch)
  const hasSession = sessionEpoch >= 0 && getSessionModel() !== null

  if (!open || phase !== 'workspace' || busy || !hasSession) return null

  const onClose = () => {
    useAppStore.getState().setTextOutcomeDialogOpen(false)
    // Automatic opening may originate from an import control that has unmounted.
    window.requestAnimationFrame(() => {
      document.querySelector<HTMLElement>('[data-testid="text-outcome-dialog-open"]')?.focus({ preventScroll: true })
    })
  }

  return (
    <AccessibleModal
      open
      wide
      focusTitle
      onClose={onClose}
      titleId="text-outcome-dialog-title"
      title={cs.pcap.outcome.textTitle}
      testId="text-outcome-dialog"
      actions={
        <Button variant="primary" onClick={onClose} data-testid="text-outcome-dialog-close">
          {cs.pcap.outcome.closeDialog}
        </Button>
      }
    >
      <TextAnonymizationOutcomePanel hideTitle />
    </AccessibleModal>
  )
}
