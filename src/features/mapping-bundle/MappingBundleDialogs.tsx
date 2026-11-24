import { AccessibleModal, Button, ExportSummary } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'

export function MappingBundleExportDialog(props: {
  onCancel: () => void
  onConfirm: () => void
  busy?: boolean
}) {
  return (
    <AccessibleModal
      open
      onClose={props.busy ? () => {} : props.onCancel}
      titleId="bundle-export-title"
      title={cs.bundle.exportTitle}
      testId="mapping-bundle-export-dialog"
      actions={
        <>
          <Button variant="ghost" disabled={props.busy} onClick={props.onCancel}>
            {cs.export.cancel}
          </Button>
          <Button
            variant="primary"
            data-testid="mapping-bundle-export-confirm"
            data-autofocus
            disabled={props.busy}
            onClick={props.onConfirm}
          >
            {cs.bundle.exportConfirm}
          </Button>
        </>
      }
    >
      <ExportSummary>
        <section className="ds-export-summary__section">
          <p className="modal__impact">{cs.bundle.exportWarning}</p>
        </section>
      </ExportSummary>
      {props.busy ? (
        <p role="status" aria-live="polite">
          {cs.bundle.exporting}
        </p>
      ) : null}
    </AccessibleModal>
  )
}

export function MappingBundleImportDialog(props: {
  onCancel: () => void
  onPickFile: () => void
  fileName: string | null
  onConfirm: () => void
  busy?: boolean
}) {
  return (
    <AccessibleModal
      open
      onClose={props.busy ? () => {} : props.onCancel}
      titleId="bundle-import-title"
      title={cs.bundle.importTitle}
      testId="mapping-bundle-import-dialog"
      actions={
        <>
          <Button variant="ghost" disabled={props.busy} onClick={props.onCancel}>
            {cs.export.cancel}
          </Button>
          <Button
            variant="primary"
            data-testid="mapping-bundle-import-confirm"
            disabled={props.busy || !props.fileName}
            onClick={props.onConfirm}
          >
            {cs.bundle.importConfirm}
          </Button>
        </>
      }
    >
      <ExportSummary>
        <section className="ds-export-summary__section">
          <p className="modal__impact">{cs.bundle.importWarning}</p>
        </section>
      </ExportSummary>
      <Button variant="secondary" disabled={props.busy} onClick={props.onPickFile}>
        {cs.bundle.chooseFile}
      </Button>
      {props.fileName ? <p data-testid="mapping-bundle-import-file">{props.fileName}</p> : null}
      {props.busy ? (
        <p role="status" aria-live="polite">
          {cs.bundle.importing}
        </p>
      ) : null}
    </AccessibleModal>
  )
}
