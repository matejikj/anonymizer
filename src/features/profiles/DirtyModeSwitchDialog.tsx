import { useAppStore } from '../../app/store.ts'
import {
  revertActiveProfile,
  saveActiveProfile,
} from './profileController.ts'
import { AccessibleModal, Button } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'

export function DirtyModeSwitchDialog() {
  const pendingMode = useAppStore((s) => s.pendingSwitchMode)

  const close = () => {
    useAppStore.getState().setProfileDialog('none')
    useAppStore.getState().setPendingSwitchMode(null)
  }

  const finishSwitch = () => {
    if (!pendingMode) return
    useAppStore.getState().setActiveMode(pendingMode)
    close()
  }

  return (
    <AccessibleModal
      open
      onClose={close}
      titleId="dirty-mode-switch-title"
      title={cs.profiles.dirtyModeTitle}
      testId="dirty-mode-switch-dialog"
      actions={
        <>
          <Button variant="ghost" data-testid="dirty-mode-stay" onClick={close}>
            {cs.profiles.stay}
          </Button>
          <Button
            variant="secondary"
            data-testid="dirty-mode-discard"
            onClick={() => {
              if (!pendingMode) return
              void revertActiveProfile().then(finishSwitch)
            }}
          >
            {cs.profiles.discard}
          </Button>
          <Button
            variant="primary"
            data-testid="dirty-mode-save"
            data-autofocus
            onClick={() => {
              if (!pendingMode) return
              void saveActiveProfile().then(finishSwitch)
            }}
          >
            {cs.profiles.saveAndSwitchMode}
          </Button>
        </>
      }
    >
      <p>{cs.profiles.dirtyModeBody}</p>
    </AccessibleModal>
  )
}
