import { useRef, useState } from 'react'
import {
  buildImportPreview,
  commitImport,
  type ImportPreview,
} from './profileController.ts'
import { useAppStore } from '../../app/store.ts'
import { ModalPortal } from '../../components/ui/ModalPortal.tsx'
import { useModalFocusTrap } from '../../components/ui/useModalFocusTrap.ts'
import { Button } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'

export function ImportProfileDialog(props: { onClose: () => void }) {
  const dialogRef = useRef<HTMLDivElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const [text, setText] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [preview, setPreview] = useState<ImportPreview | null>(null)
  const [mode, setMode] = useState<'copy' | 'replace'>('copy')
  const [busy, setBusy] = useState(false)

  useModalFocusTrap({ open: true, onClose: props.onClose, dialogRef })

  const runPreview = async (source: string) => {
    setError(null)
    setPreview(null)
    const result = await buildImportPreview(source)
    if (!result.ok) {
      const first = result.issues[0]
      const loc = result.parseError
        ? ` (ř. ${result.parseError.line}, sl. ${result.parseError.column})`
        : ''
      setError(
        result.schemaTooNew
          ? cs.profiles.schemaTooNew
          : `${first?.path ?? ''}: ${first?.message ?? cs.profiles.importInvalid}${loc}`,
      )
      return
    }
    setPreview(result.preview)
    setMode(result.preview.collision ? 'copy' : 'copy')
  }

  const onFile = async (file: File | null) => {
    if (!file) return
    const head = new Uint8Array(await file.slice(0, 8).arrayBuffer())
    const recoveryMagic =
      head.byteLength >= 8
      && head[0] === 0x52
      && head[1] === 0x4e
      && head[2] === 0x44
      && head[3] === 0x50
      && head[4] === 0x43
      && head[5] === 0x41
      && head[6] === 0x50
      && head[7] === 0x52
    if (recoveryMagic) {
      setPreview(null)
      setError(cs.profiles.importRecoveryRejected)
      return
    }
    const source = await file.text()
    setText(source)
    await runPreview(source)
  }

  const onConfirm = async () => {
    if (!preview) return
    setBusy(true)
    try {
      await commitImport(preview.config, preview.collision ? mode : 'replace')
      useAppStore.getState().setToast({ message: cs.profiles.imported })
      props.onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : cs.profiles.importInvalid)
    } finally {
      setBusy(false)
    }
  }

  return (
    <ModalPortal>
      <div
        className="modal-backdrop"
        role="presentation"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) props.onClose()
        }}
      >
        <div
          ref={dialogRef}
          className="modal modal--wide"
          role="dialog"
          aria-modal="true"
          aria-labelledby="import-profile-title"
          data-testid="import-profile-dialog"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault()
            void onFile(e.dataTransfer.files?.[0] ?? null)
          }}
        >
          <h2 id="import-profile-title">{cs.profiles.importTitle}</h2>
          <p className="rule-form__hint">{cs.profiles.importLead}</p>

          <div className="modal__actions" style={{ justifyContent: 'flex-start' }}>
            <Button
              variant="secondary"
              data-testid="import-pick-file"
              onClick={() => fileRef.current?.click()}
            >
              {cs.profiles.chooseFile}
            </Button>
            <input
              ref={fileRef}
              type="file"
              accept=".json,.rnd-log-anonymizer.json,application/json"
              className="visually-hidden"
              onChange={(e) => void onFile(e.target.files?.[0] ?? null)}
            />
          </div>

          <label className="rule-form__field">
            <span>{cs.profiles.pasteJson}</span>
            <textarea
              rows={8}
              value={text}
              data-testid="import-json-text"
              placeholder="{ … }"
              onChange={(e) => setText(e.target.value)}
            />
          </label>
          <Button variant="secondary" data-testid="import-preview" onClick={() => void runPreview(text)}>
            {cs.profiles.preview}
          </Button>

          {error ? (
            <p className="rule-form__error" role="alert" data-testid="import-error">
              {error}
            </p>
          ) : null}

          {preview ? (
            <div className="import-preview" data-testid="import-preview-panel">
              <p>
                <strong>{preview.summary.name}</strong> · {preview.summary.ruleCount}{' '}
                {cs.profiles.rulesCount}
              </p>
              {preview.summary.disabledBuiltins.length > 0 ? (
                <p>
                  {cs.profiles.disabledBuiltins}: {preview.summary.disabledBuiltins.join(', ')}
                </p>
              ) : null}
              {preview.summary.literalCount > 0 ? (
                <p className="rule-form__warn">{cs.profiles.literalWarning}</p>
              ) : null}
              {preview.impact ? (
                <p data-testid="import-impact">
                  {cs.profiles.impact
                    .replace('{before}', String(preview.impact.before))
                    .replace('{after}', String(preview.impact.after))}
                </p>
              ) : null}
              {preview.collision ? (
                <fieldset className="rule-form__fieldset">
                  <legend>{cs.profiles.collisionTitle}</legend>
                  <label className="rule-form__radio">
                    <input
                      type="radio"
                      name="collision"
                      checked={mode === 'copy'}
                      data-testid="import-as-copy"
                      onChange={() => setMode('copy')}
                    />
                    {cs.profiles.importAsCopy}
                  </label>
                  <label className="rule-form__radio">
                    <input
                      type="radio"
                      name="collision"
                      checked={mode === 'replace'}
                      data-testid="import-replace"
                      onChange={() => setMode('replace')}
                    />
                    {cs.profiles.importReplace}
                  </label>
                </fieldset>
              ) : null}
            </div>
          ) : null}

          <div className="modal__actions">
            <Button variant="ghost" onClick={props.onClose}>
              {cs.profiles.cancel}
            </Button>
            <Button
              variant="primary"
              data-testid="import-confirm"
              disabled={!preview || busy}
              busy={busy}
              onClick={() => void onConfirm()}
            >
              {busy ? cs.profiles.importing : cs.profiles.confirmImport}
            </Button>
          </div>
        </div>
      </div>
    </ModalPortal>
  )
}
