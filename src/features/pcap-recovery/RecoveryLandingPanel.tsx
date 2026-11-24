import { useId, useRef, useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import { mergeRecoveryPairFiles } from '../../pcap/recovery/restore/classifyRecoveryFiles.ts'
import { startPcapRecoverySession, RecoveryBootstrapError } from './recoveryWorkspaceBootstrap.ts'
import { Button } from '../../design-system/Button.tsx'

/**
 * Landing utility — pick anonymized PCAP + recovery file. Secondary to anonymize hero.
 * Opens the pair without a passphrase (plaintext recovery frames).
 */
export function RecoveryLandingPanel() {
  const fileRef = useRef<HTMLInputElement>(null)
  const inputId = useId()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const openPicker = () => {
    fileRef.current?.click()
  }

  const ingest = async (files: readonly File[] | null) => {
    if (!files?.length) return
    setError(null)
    const merged = await mergeRecoveryPairFiles({
      incoming: files,
      anonymizedFile: null,
      recoveryFile: null,
    })
    if (merged.unknownCount > 0) {
      setError(cs.pcap.recovery.unknownFile)
      return
    }
    if (merged.duplicateRole) {
      setError(cs.pcap.recovery.duplicateRole)
      return
    }
    if (!merged.anonymizedFile || !merged.recoveryFile) {
      setError(cs.pcap.recovery.needBothFiles)
      return
    }
    setBusy(true)
    try {
      await startPcapRecoverySession({
        anonymizedFile: merged.anonymizedFile,
        recoveryFile: merged.recoveryFile,
      })
    } catch (err) {
      setError(err instanceof RecoveryBootstrapError ? err.message : cs.pcap.recovery.preflightFailed)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="empty__utility-item" data-testid="recovery-landing-panel">
      <label className="visually-hidden" htmlFor={inputId}>
        {cs.pcap.recovery.chooseFiles}
      </label>
      <input
        id={inputId}
        ref={fileRef}
        type="file"
        accept=".pcap,.pcapng,.rnd-pcap-recovery.bin,.rnd-pcap-recovery,.bin,application/octet-stream"
        multiple
        className="visually-hidden"
        data-testid="recovery-file-input"
        onChange={(e) => {
          const files = e.target.files ? [...e.target.files] : null
          e.target.value = ''
          void ingest(files)
        }}
      />
      <Button
        variant="link"
        onClick={openPicker}
        disabled={busy}
        data-testid="recovery-landing-choose"
        aria-label={cs.empty.recoveryHeading}
      >
        {busy ? cs.pcap.recovery.busy : cs.empty.recoveryHeading}
      </Button>
      {/* Legacy test hook for the former dropzone control. */}
      <span className="visually-hidden" data-testid="recovery-landing-open">
        {cs.pcap.recovery.chooseFiles}
      </span>
      {error ? (
        <p className="empty__utility-error" role="alert" data-testid="recovery-landing-error">
          {error}
        </p>
      ) : null}
    </div>
  )
}
