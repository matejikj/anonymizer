import { wipeLocalProfilesAndPreferences } from './profileController.ts'
import { useAppStore } from '../../app/store.ts'
import { AccessibleModal, Button } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'

export function ClearDataDialog(props: { onClose: () => void }) {
  return (
    <AccessibleModal
      open
      onClose={props.onClose}
      titleId="clear-data-title"
      title={cs.profiles.clearTitle}
      testId="clear-data-dialog"
      actions={
        <>
          <Button variant="ghost" onClick={props.onClose}>
            {cs.profiles.cancel}
          </Button>
          <Button
            variant="destructive"
            data-testid="clear-data-confirm"
            onClick={() => {
              void wipeLocalProfilesAndPreferences().then(() => {
                useAppStore.getState().setToast({ message: cs.profiles.cleared })
                props.onClose()
              })
            }}
          >
            {cs.profiles.clearConfirm}
          </Button>
        </>
      }
    >
      <p>{cs.profiles.clearBody}</p>
      <ul className="modal-list">
        <li>{cs.profiles.clearItemProfiles}</li>
        <li>{cs.profiles.clearItemPrefs}</li>
      </ul>
      <p className="rule-form__hint">{cs.profiles.clearKeepLog}</p>
    </AccessibleModal>
  )
}
