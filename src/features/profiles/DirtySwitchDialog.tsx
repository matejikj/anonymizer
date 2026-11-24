import { useAppStore } from '../../app/store.ts'
import {
  activateProfile,
  saveActiveProfile,
} from './profileController.ts'
import { AccessibleModal, Button } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'

export function DirtySwitchDialog() {
  const pendingId = useAppStore((s) => s.pendingSwitchProfileId)

  const close = () => {
    useAppStore.getState().setProfileDialog('none')
    useAppStore.getState().setPendingSwitchProfileId(null)
  }

  return (
    <AccessibleModal
      open
      onClose={close}
      titleId="dirty-switch-title"
      title={cs.profiles.dirtyTitle}
      testId="dirty-switch-dialog"
      actions={
        <>
          <Button variant="ghost" onClick={close}>
            {cs.profiles.stay}
          </Button>
          <Button
            variant="secondary"
            data-testid="dirty-discard"
            onClick={() => {
              if (!pendingId) return
              void activateProfile(pendingId, { force: true }).then(close)
            }}
          >
            {cs.profiles.discard}
          </Button>
          <Button
            variant="primary"
            data-testid="dirty-save"
            data-autofocus
            onClick={() => {
              if (!pendingId) return
              void saveActiveProfile().then(() =>
                activateProfile(pendingId, { force: true }).then(close),
              )
            }}
          >
            {cs.profiles.saveAndSwitch}
          </Button>
        </>
      }
    >
      <p>{cs.profiles.dirtyBody}</p>
    </AccessibleModal>
  )
}
