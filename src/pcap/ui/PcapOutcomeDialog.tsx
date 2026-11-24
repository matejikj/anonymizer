/**
 * T10 — closable „Výsledek anonymizace“ dialog after PCAP analysis.
 * Dual Original|Anonymized editors stay on the main layout behind the modal.
 */

import { AccessibleModal, Button } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'
import { AnonymizationOutcomePanel } from './AnonymizationOutcomePanel.tsx'
import { getAnonymizationOutcome } from './getAnonymizationOutcome.ts'
import { usePcapStore } from './pcapStore.ts'

export function PcapOutcomeDialog() {
  const open = usePcapStore((s) => s.outcomeDialogOpen)
  const setOpen = usePcapStore((s) => s.setOutcomeDialogOpen)
  const phase = usePcapStore((s) => s.phase)
  const outcome = open && phase === 'workspace' ? getAnonymizationOutcome() : null

  if (!open || !outcome) return null

  const onClose = () => setOpen(false)

  return (
    <AccessibleModal
      open
      wide
      focusTitle
      onClose={onClose}
      titleId="pcap-outcome-dialog-title"
      title={cs.pcap.outcome.title}
      testId="pcap-outcome-dialog"
      actions={
        <Button variant="primary" onClick={onClose} data-testid="pcap-outcome-dialog-close">
          {cs.pcap.outcome.closeDialog}
        </Button>
      }
    >
      <AnonymizationOutcomePanel
        outcome={outcome}
        className="pcap-outcome-dialog__panel"
        testId="pcap-workspace-outcome"
        hideTitle
        announceLive
        onAfterShowPackets={onClose}
      />
    </AccessibleModal>
  )
}
