import { useEffect, useId, useMemo, useState } from 'react'
import { AccessibleDrawer } from '../../components/ui/AccessibleDrawer.tsx'
import { Button, ExportSummary } from '../../design-system/index.ts'
import { IconCheck, IconX } from '../../components/ui/icons.tsx'
import { cs } from '../../i18n/cs.ts'
import {
  buildCorrelationExportPreview,
  isExportPreviewStale,
} from '../../correlation/export/correlationExportController.ts'
import type {
  CorrelationExportPreview,
  CorrelationExportScope,
} from '../../correlation/export/correlationExportTypes.ts'
import { useAppStore } from '../../app/store.ts'

function exposedLabel(hint: string | null): string {
  if (hint === 'pcap-exposed') return cs.correlationExport.exposedPcap
  return cs.correlationExport.exposedText
}

export function CorrelationExportDialog(props: {
  multiDownloadWarning: boolean
  canPickDirectory: boolean
  busy?: boolean
  currentSourceId: string | null
  onCancel: () => void
  onExport: (input: {
    scope: CorrelationExportScope
    partial: boolean
    preferDirectoryPicker: boolean
    expectedGenerationId: string | null
    expectedMappingRevision: number | null
  }) => void
}) {
  void props.multiDownloadWarning
  const titleId = useId()
  const correlationEpoch = useAppStore((s) => s.correlationEpoch)
  const [scope, setScope] = useState<CorrelationExportScope>('set')
  /** Default matches single-file text/PCAP: browser download to Downloads. */
  const [destination, setDestination] = useState<'download' | 'directory'>('download')
  const [staleAck, setStaleAck] = useState(0)

  const preview = useMemo(
    () =>
      buildCorrelationExportPreview({
        scope,
        currentSourceId: props.currentSourceId,
      }),
    [scope, props.currentSourceId, correlationEpoch, staleAck],
  )

  const stale = isExportPreviewStale(preview)
  const exportable = preview.files.filter((f) => f.exportable)
  const exportCount = exportable.length + (preview.includeManifest ? 1 : 0)

  useEffect(() => {
    if (!preview.canChooseCurrent && scope === 'current') setScope('set')
  }, [preview.canChooseCurrent, scope])

  useEffect(() => {
    if (!props.canPickDirectory && destination === 'directory') setDestination('download')
  }, [props.canPickDirectory, destination])

  const emitExport = (partial: boolean) => {
    props.onExport({
      scope,
      partial,
      preferDirectoryPicker: destination === 'directory',
      expectedGenerationId: preview.generationId,
      expectedMappingRevision: preview.mappingRevision,
    })
  }

  return (
    <AccessibleDrawer
      open
      onClose={props.busy ? () => {} : props.onCancel}
      titleId={titleId}
      title={cs.correlationExport.dialogTitle}
      testId="correlation-export-dialog"
      footer={
        <>
          <Button variant="ghost" disabled={props.busy} onClick={props.onCancel}>
            {cs.export.cancel}
          </Button>
          {preview.partialOnly ? (
            <Button
              variant="primary"
              data-testid="correlation-export-partial"
              disabled={props.busy || exportable.length === 0 || stale}
              onClick={() => emitExport(true)}
            >
              {cs.correlationExport.exportPartial(exportable.length, preview.files.length)}
            </Button>
          ) : (
            <Button
              variant="primary"
              data-testid="correlation-export-confirm"
              disabled={props.busy || !preview.canExportAll || stale}
              onClick={() => emitExport(false)}
            >
              {cs.correlationExport.exportCount(exportCount)}
            </Button>
          )}
        </>
      }
    >
      <ExportSummary>
        <section className="ds-export-summary__section">
          <p className="corr-export__counts" data-testid="correlation-export-counts">
            {cs.correlationExport.dataFilesCount(preview.dataFileCount)}
            {preview.companionFileCount > 0
              ? ` · ${cs.correlationExport.companionFilesCount(preview.companionFileCount)}`
              : ''}
          </p>
        </section>
      </ExportSummary>

      <fieldset className="corr-export__scope" data-testid="correlation-export-destination">
        <legend>{cs.correlationExport.destinationLabel}</legend>
        <label className="corr-export__scope-option">
          <input
            type="radio"
            name="corr-export-destination"
            value="download"
            checked={destination === 'download'}
            onChange={() => setDestination('download')}
            data-testid="correlation-export-dest-download"
          />
          {cs.correlationExport.destinationDownload}
        </label>
        <label className="corr-export__scope-option">
          <input
            type="radio"
            name="corr-export-destination"
            value="directory"
            checked={destination === 'directory'}
            disabled={!props.canPickDirectory}
            onChange={() => setDestination('directory')}
            data-testid="correlation-export-dest-directory"
            title={
              props.canPickDirectory ? undefined : cs.correlationExport.destinationDirectoryUnavailable
            }
          />
          {cs.correlationExport.destinationDirectory}
        </label>
      </fieldset>

      <fieldset className="corr-export__scope" data-testid="correlation-export-scope">
        <legend>{cs.correlationExport.scopeLabel}</legend>
        <label className="corr-export__scope-option">
          <input
            type="radio"
            name="corr-export-scope"
            value="set"
            checked={scope === 'set'}
            onChange={() => setScope('set')}
            data-testid="correlation-export-scope-set"
          />
          {cs.correlationExport.scopeSet}
        </label>
        <label className="corr-export__scope-option">
          <input
            type="radio"
            name="corr-export-scope"
            value="current"
            checked={scope === 'current'}
            disabled={!preview.canChooseCurrent}
            onChange={() => setScope('current')}
            data-testid="correlation-export-scope-current"
            title={preview.canChooseCurrent ? undefined : cs.correlationExport.scopeCurrentDisabled}
          />
          {cs.correlationExport.scopeCurrent}
        </label>
      </fieldset>

      {stale ? (
        <p className="corr-export__stale" role="alert" data-testid="correlation-export-stale">
          {cs.correlationExport.stalePreview}{' '}
          <Button
            variant="ghost"
            data-testid="correlation-export-stale-refresh"
            onClick={() => setStaleAck((n) => n + 1)}
          >
            {cs.correlationExport.staleRefresh}
          </Button>
        </p>
      ) : null}

      <ul className="corr-export__file-list" data-testid="correlation-export-file-list">
        {preview.files.map((file) => (
          <li
            key={file.sourceId}
            className={
              file.security === 'exposed'
                ? 'corr-export__file corr-export__file--exposed'
                : file.exportable
                  ? 'corr-export__file'
                  : 'corr-export__file corr-export__file--blocked'
            }
            data-testid={`correlation-export-file-${file.sourceId}`}
            data-exportable={file.exportable ? 'true' : 'false'}
          >
            {file.exportable ? (
              <IconCheck className="corr-export__file-icon corr-export__file-icon--ok" aria-hidden="true" />
            ) : (
              <IconX className="corr-export__file-icon corr-export__file-icon--blocked" aria-hidden="true" />
            )}
            <span className="corr-export__file-names">
              <span className="corr-export__input" title={file.inputFileName}>
                {file.inputFileName}
              </span>
              <span className="corr-export__arrow" aria-hidden="true">
                →
              </span>
              <span className="corr-export__output" title={file.outputFileName}>
                {file.outputFileName}
              </span>
            </span>
            {file.security === 'exposed' && file.exportable ? (
              <span className="corr-export__exposed-note">{exposedLabel(file.exposedHint)}</span>
            ) : null}
            {!file.exportable ? (
              <span className="corr-export__blocked-note">
                {file.skipDetail ?? cs.correlationExport.blockedHint}
              </span>
            ) : null}
          </li>
        ))}
        {preview.includeManifest ? (
          <li className="corr-export__file corr-export__file--manifest" data-artifact="manifest">
            <IconCheck className="corr-export__file-icon corr-export__file-icon--ok" aria-hidden="true" />
            <span>{preview.manifestFileName}</span>
          </li>
        ) : null}
      </ul>
      {preview.exposedCount > 0 ? (
        <p className="corr-export__warn-note" role="status" data-testid="correlation-export-exposed-note">
          {cs.correlationExport.exposedExportNote(preview.exposedCount)}
        </p>
      ) : null}
    </AccessibleDrawer>
  )
}

/** @deprecated Prefer building preview inside the dialog; kept for tests. */
export type { CorrelationExportPreview }
