import { useId, useRef, useState, type DragEvent, type FormEvent, type KeyboardEvent } from 'react'
import { cs } from '../../i18n/cs.ts'
import { useAppStore } from '../../app/store.ts'
import {
  handleUniversalFileDrop,
  singleFileStagingErrorMessage,
  UNIVERSAL_FILE_ACCEPT,
} from '../../correlation/import/correlationImportController.ts'
import { startTextSession } from '../../app/sessionLifecycleCoordinator.ts'
import { IconExport } from '../../components/ui/icons.tsx'
import { SAMPLE_LOG } from '../import-log/sampleLog.ts'
import { ImportCancelledError } from '../import-log/streamImport.ts'
import {
  TEXT_ENCODING_LABELS,
  labelDisplayName,
  type TextEncodingLabel,
} from '../import-log/textEncoding.ts'
import { Button } from '../../design-system/Button.tsx'
import { ResolveReturnLandingPanel } from '../resolve-only/ResolveReturnLandingPanel.tsx'
import { RecoveryLandingPanel } from '../pcap-recovery/RecoveryLandingPanel.tsx'

/**
 * Landing — Forensic Bench empty: brand · one sentence · one dropzone · utilities.
 */
export function MultiSourceDropzone() {
  const inputId = useId()
  const textareaId = useId()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [pasteOpen, setPasteOpen] = useState(false)
  const [pasteText, setPasteText] = useState('')
  const [localError, setLocalError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const setStatusMessage = useAppStore((s) => s.setStatusMessage)
  const setLastError = useAppStore((s) => s.setLastError)
  const lastError = useAppStore((s) => s.lastError)
  const encodingOverride = useAppStore((s) => s.textEncodingOverride)
  const setTextEncodingOverride = useAppStore((s) => s.setTextEncodingOverride)
  const encodingSelectId = useId()

  const onChooseFiles = () => fileInputRef.current?.click()

  const ingestFiles = async (files: FileList | null) => {
    if (!files?.length) return
    setLocalError(null)
    setLastError(null)
    setBusy(true)
    try {
      await handleUniversalFileDrop([...files])
      const inline = singleFileStagingErrorMessage()
      if (inline) setLocalError(inline)
    } catch (err) {
      const message = err instanceof Error ? err.message : cs.errors.importFailed
      setLocalError(message)
      setStatusMessage(cs.status.ready)
    } finally {
      setBusy(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const onFileChange = (files: FileList | null) => {
    void ingestFiles(files)
  }

  const onDragOver = (event: DragEvent) => {
    event.preventDefault()
    setDragging(true)
  }

  const onDragLeave = () => setDragging(false)

  const onDrop = (event: DragEvent) => {
    event.preventDefault()
    setDragging(false)
    void ingestFiles(event.dataTransfer.files)
  }

  const onPasteClipboard = async () => {
    setLocalError(null)
    setPasteOpen(true)
    try {
      const text = await navigator.clipboard.readText()
      if (!text.trim()) {
        setLocalError(cs.errors.emptyPaste)
        return
      }
      setPasteText(text)
      setStatusMessage(cs.empty.clipboardLoaded)
    } catch {
      setLocalError(cs.errors.clipboardDenied)
    }
  }

  const onAnalyzePaste = async (event: FormEvent) => {
    event.preventDefault()
    if (!pasteText.trim()) {
      setLocalError(cs.errors.emptyPaste)
      return
    }
    setLocalError(null)
    setLastError(null)
    setBusy(true)
    try {
      await startTextSession({ text: pasteText })
    } catch (err) {
      if (err instanceof ImportCancelledError) return
      const message = err instanceof Error ? err.message : cs.errors.importFailed
      setLocalError(message)
      setStatusMessage(cs.status.ready)
    } finally {
      setBusy(false)
    }
  }

  const onTrySample = async () => {
    setLocalError(null)
    setLastError(null)
    setBusy(true)
    try {
      await startTextSession({ text: SAMPLE_LOG })
    } catch (err) {
      if (err instanceof ImportCancelledError) return
      const message = err instanceof Error ? err.message : cs.errors.importFailed
      setLocalError(message)
    } finally {
      setBusy(false)
    }
  }

  const onDropzoneKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      onChooseFiles()
    }
  }

  const displayError = localError || lastError

  return (
    <section className="empty empty--landing" aria-labelledby="empty-title" data-reference="landing" data-testid="landing">
      <div className="empty__intro">
        <h1 id="empty-title" className="type-page-title">
          {cs.empty.landingLead}
        </h1>
      </div>

      <div className="empty__hero" data-testid="landing-anonymize-panel">
        <div
          className={`dropzone dropzone--hero${dragging ? ' dropzone--active' : ''}${busy ? ' dropzone--busy' : ''}`}
          role="button"
          tabIndex={busy ? -1 : 0}
          aria-label={cs.a11y.dropzone}
          aria-disabled={busy}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          onDrop={onDrop}
          onKeyDown={onDropzoneKeyDown}
          onClick={() => {
            if (!busy) onChooseFiles()
          }}
          data-testid="multi-source-dropzone"
        >
          <span className="dropzone__icon" aria-hidden="true">
            <IconExport size={20} />
          </span>
          <strong className="dropzone__label">{cs.empty.dropzoneLabel}</strong>
          <span className="dropzone__hint type-meta">{cs.empty.dropzoneHint}</span>
        </div>

        <label className="visually-hidden" htmlFor={inputId}>
          {cs.empty.chooseFile}
        </label>
        <input
          id={inputId}
          ref={fileInputRef}
          className="visually-hidden"
          type="file"
          accept={UNIVERSAL_FILE_ACCEPT}
          multiple
          disabled={busy}
          data-testid="file-input"
          onChange={(e) => onFileChange(e.target.files)}
        />

        <div className="empty__encoding" data-testid="text-encoding-override">
          <label htmlFor={encodingSelectId} className="type-meta">
            {cs.empty.encodingLabel}
          </label>
          <select
            id={encodingSelectId}
            value={encodingOverride ?? ''}
            disabled={busy}
            data-testid="text-encoding-select"
            onChange={(e) => {
              const v = e.target.value
              setTextEncodingOverride(v === '' ? null : (v as TextEncodingLabel))
            }}
          >
            <option value="">{cs.empty.encodingAuto}</option>
            {TEXT_ENCODING_LABELS.map((label) => (
              <option key={label} value={label}>
                {labelDisplayName(label)}
              </option>
            ))}
          </select>
          <p className="type-meta">{cs.empty.encodingHint}</p>
        </div>

        <div className="empty__secondary-actions">
          <Button
            variant="link"
            data-testid="paste-toggle"
            aria-expanded={pasteOpen}
            onClick={() => setPasteOpen((v) => !v)}
            disabled={busy}
          >
            {cs.empty.pasteToggle}
          </Button>
          <span className="empty__secondary-sep" aria-hidden="true">
            ·
          </span>
          <Button variant="link" onClick={() => void onTrySample()} disabled={busy} data-testid="try-sample">
            {cs.empty.trySample}
          </Button>
        </div>

        {pasteOpen ? (
          <form className="empty__paste" onSubmit={(e) => void onAnalyzePaste(e)} data-testid="landing-paste">
            <label htmlFor={textareaId}>{cs.empty.textareaLabel}</label>
            <textarea
              id={textareaId}
              value={pasteText}
              onChange={(e) => setPasteText(e.target.value)}
              placeholder={cs.empty.textareaPlaceholder}
              rows={8}
              disabled={busy}
              data-testid="paste-textarea"
            />
            <div className="empty__actions">
              <Button type="submit" variant="primary" disabled={busy || !pasteText.trim()} data-testid="analyze-paste">
                {cs.empty.analyzePaste}
              </Button>
              <Button type="button" variant="ghost" onClick={() => void onPasteClipboard()} disabled={busy} data-testid="paste-clipboard">
                {cs.empty.pasteClipboard}
              </Button>
            </div>
          </form>
        ) : null}

        {displayError ? (
          <p className="empty__error" role="alert" data-testid="empty-error">
            {displayError}
          </p>
        ) : null}
      </div>

      <nav className="empty__utilities" aria-label={cs.empty.utilitiesLabel} data-testid="landing-utilities">
        <ResolveReturnLandingPanel />
        <span className="empty__utilities-sep" aria-hidden="true">
          ·
        </span>
        <RecoveryLandingPanel />
      </nav>
    </section>
  )
}
