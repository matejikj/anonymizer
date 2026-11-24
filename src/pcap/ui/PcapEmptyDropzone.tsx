import { useId, useRef, useState, type DragEvent } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { startPcapSession } from '../../app/sessionLifecycleCoordinator.ts'
import { Button } from '../../design-system/index.ts'

export function PcapEmptyDropzone() {
  const inputId = useId()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)
  const activeLevel = usePcapStore((s) => s.activePcapLevel)
  const errorMessage = usePcapStore((s) => s.errorMessage)
  const setErrorMessage = usePcapStore((s) => s.setErrorMessage)

  const profileSentence = cs.pcap.empty.presetSentence.replace(
    '{name}',
    activeLevel === 'diagnostic'
      ? cs.pcap.presets.diagnosticName
      : cs.pcap.presets.highPrivacyName,
  )

  const startFile = async (file: File) => {
    setErrorMessage(null)
    setBusy(true)
    try {
      await startPcapSession(file)
    } finally {
      setBusy(false)
    }
  }

  const onFileChange = (files: FileList | null) => {
    const file = files?.[0]
    if (!file) return
    void startFile(file)
  }

  const onDragOver = (event: DragEvent) => {
    event.preventDefault()
    setDragging(true)
  }

  const onDrop = (event: DragEvent) => {
    event.preventDefault()
    setDragging(false)
    onFileChange(event.dataTransfer.files)
  }

  return (
    <div className="pcap-empty" data-testid="pcap-empty">
      <p className="pcap-empty__preset" role="status">
        {profileSentence}
      </p>

      <div
        className={`dropzone pcap-dropzone${dragging ? ' dropzone--active' : ''}${busy ? ' dropzone--busy' : ''}`}
        role="button"
        tabIndex={0}
        aria-label={cs.pcap.empty.dropzoneLabel}
        data-testid="pcap-dropzone"
        onDragOver={onDragOver}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => fileInputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            fileInputRef.current?.click()
          }
        }}
      >
        <strong>{cs.pcap.empty.dropzoneLabel}</strong>
        <span>{cs.pcap.empty.dropzoneHint}</span>
      </div>

      <div className="pcap-empty__actions">
        <Button
          variant="primary"
          disabled={busy}
          data-testid="pcap-choose-file"
          onClick={() => fileInputRef.current?.click()}
        >
          {cs.pcap.empty.chooseFile}
        </Button>
        <label className="visually-hidden" htmlFor={inputId}>
          {cs.pcap.empty.chooseFile}
        </label>
        <input
          ref={fileInputRef}
          id={inputId}
          type="file"
          accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/octet-stream"
          className="visually-hidden"
          tabIndex={-1}
          data-testid="pcap-file-input"
          onChange={(e) => onFileChange(e.target.files)}
        />
      </div>

      {errorMessage ? (
        <p className="pcap-empty__error" role="alert" data-testid="pcap-load-error">
          {errorMessage}
        </p>
      ) : null}

      <p className="pcap-empty__narrow">{cs.pcap.empty.narrowHint}</p>
    </div>
  )
}
