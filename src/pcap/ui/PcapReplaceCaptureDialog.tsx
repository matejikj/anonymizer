import { usePcapStore } from './pcapStore.ts'
import { confirmPcapReplace, cancelPcapReplace } from './pcapLoadController.ts'
import { AccessibleModal, Button } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'

export function PcapReplaceCaptureDialog() {
  const fileName = usePcapStore((s) => s.pendingReplaceFileName)

  if (!fileName) return null

  return (
    <AccessibleModal
      open
      onClose={() => cancelPcapReplace()}
      titleId="pcap-replace-title"
      title={cs.pcap.replace.title}
      testId="pcap-replace-dialog"
      actions={
        <>
          <Button variant="ghost" data-testid="pcap-replace-cancel" onClick={() => cancelPcapReplace()}>
            {cs.pcap.replace.cancel}
          </Button>
          <Button
            variant="primary"
            data-testid="pcap-replace-confirm"
            data-autofocus
            onClick={() => void confirmPcapReplace()}
          >
            {cs.pcap.replace.confirm}
          </Button>
        </>
      }
    >
      <p>{cs.pcap.replace.body.replace('{name}', fileName)}</p>
    </AccessibleModal>
  )
}
