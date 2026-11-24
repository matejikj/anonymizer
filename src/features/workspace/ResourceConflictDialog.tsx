import { useAppStore } from '../../app/store.ts'
import { AccessibleModal, Button } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'
import {
  cancelResourceConflict,
  confirmResourceConflictChoice,
} from '../../app/resourceConflictPrompt.ts'

export function ResourceConflictDialog(): React.ReactElement | null {
  const conflict = useAppStore((s) => s.resourceConflict)

  if (!conflict) return null

  const body =
    conflict.kind === 'pcap-over-text'
      ? cs.resourceConflict.pcapOverText
      : cs.resourceConflict.textOverPcap

  return (
    <AccessibleModal
      open
      onClose={cancelResourceConflict}
      titleId="resource-conflict-title"
      title={cs.resourceConflict.title}
      testId="resource-conflict-dialog"
      actions={
        <>
          <Button variant="ghost" data-testid="resource-conflict-cancel" onClick={cancelResourceConflict}>
            {cs.resourceConflict.cancel}
          </Button>
          <Button
            variant="primary"
            data-testid="resource-conflict-confirm"
            data-autofocus
            onClick={confirmResourceConflictChoice}
          >
            {cs.resourceConflict.confirm}
          </Button>
        </>
      }
    >
      <p>{body}</p>
      <p className="modal__impact">{cs.resourceConflict.impact}</p>
    </AccessibleModal>
  )
}
