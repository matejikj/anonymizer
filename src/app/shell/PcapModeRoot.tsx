import { useEffect } from 'react'
import { PcapEmptyDropzone } from '../../pcap/ui/PcapEmptyDropzone.tsx'
import { PcapProgressView } from '../../pcap/ui/PcapProgressView.tsx'
import { PcapWorkspace } from '../../pcap/ui/PcapWorkspace.tsx'
import { PcapReplaceCaptureDialog } from '../../pcap/ui/PcapReplaceCaptureDialog.tsx'
import { usePcapStore } from '../../pcap/ui/pcapStore.ts'
import { bootstrapPcapLevel } from '../../pcap/profile/pcapLevelController.ts'

export function PcapModeRoot() {
  const phase = usePcapStore((s) => s.phase)
  const replaceDialog = usePcapStore((s) => s.replaceDialog)

  useEffect(() => {
    void bootstrapPcapLevel()
  }, [])

  return (
    <div className="pcap-mode-root" data-testid="pcap-mode-root">
      {(phase === 'empty' || phase === 'error') && <PcapEmptyDropzone />}
      {(phase === 'preflight' || phase === 'analyzing') && <PcapProgressView />}
      {phase === 'workspace' && <PcapWorkspace />}
      {replaceDialog === 'open' ? <PcapReplaceCaptureDialog /> : null}
    </div>
  )
}
