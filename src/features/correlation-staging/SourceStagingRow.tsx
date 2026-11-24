import { SourceKind } from '../../domain/sourceArtifact'
import { cs } from '../../i18n/cs.ts'
import { formatStagingSize } from '../../correlation/import/stagingModel.ts'
import { formatGzipInflationNote } from '../../correlation/import/resolveInputFile.ts'
import type { StagingItem } from '../../correlation/import/types.ts'
import { FileKindBadge } from '../../components/ui/FileKindBadge.tsx'
import { StatusChip, type StatusChipTone } from '../../components/ui/StatusChip.tsx'
import { Button } from '../../design-system/index.ts'

function statusTone(item: StagingItem): StatusChipTone {
  if (item.status === 'error') return 'error'
  if (item.status === 'duplicate-warning') return 'duplicate'
  return 'ok'
}

function statusText(item: StagingItem): string {
  if (item.status === 'error') return cs.correlationStaging.statusTextError
  if (item.status === 'duplicate-warning') return cs.correlationStaging.statusTextDuplicate
  return cs.correlationStaging.statusTextReady
}

export interface SourceStagingRowProps {
  readonly item: StagingItem
  readonly highlighted?: boolean
  readonly onRemove: (id: string) => void
  readonly disabled?: boolean
}

export function SourceStagingRow({ item, highlighted, onRemove, disabled }: SourceStagingRowProps) {
  const kindForLabel =
    item.status === 'ready' || item.status === 'duplicate-warning'
      ? item.kind
      : SourceKind.Text
  const label = cs.correlationStaging.rowLabel(item.fileName, sourceKindLabel(kindForLabel))

  return (
    <li
      className={`staging-row${highlighted ? ' staging-row--highlight' : ''}${item.status === 'error' ? ' staging-row--error' : ''}`}
      data-testid={`staging-row-${item.id}`}
      aria-label={`${label}, ${statusText(item)}`}
    >
      <div className="staging-row__main">
        <span className="staging-row__status" data-testid={`staging-status-${item.id}`}>
          <StatusChip tone={statusTone(item)} label={statusText(item)} />
        </span>
        <div className="staging-row__body">
          <p className="staging-row__name" title={item.fileName}>
            {item.fileName}
          </p>
          {item.status === 'ready' || item.status === 'duplicate-warning' ? (
            <p className="staging-row__meta">
              <FileKindBadge kind={item.kind} />
              <span>{formatStagingSize(item.byteLength)}</span>
              <span>
                {cs.correlationStaging.profilePrefix}: {item.profileLabel}
              </span>
              {item.gzipInflation ? (
                <span data-testid={`staging-gzip-${item.id}`}>
                  {formatGzipInflationNote(item.gzipInflation)}
                </span>
              ) : null}
            </p>
          ) : (
            <div className="staging-row__error" role="alert">
              {item.rejection ? (
                <>
                  <p className="staging-row__error-title">{item.rejection.title}</p>
                  <p className="staging-row__error-reason">{item.rejection.reason}</p>
                  <p className="staging-row__error-action">{item.rejection.action}</p>
                  <p className="staging-row__error-type visually-hidden">
                    {item.rejection.detectedType}
                  </p>
                </>
              ) : (
                <p>{item.message}</p>
              )}
            </div>
          )}
          {item.status === 'duplicate-warning' ? (
            <p className="staging-row__warn">{cs.correlationStaging.duplicateHint(item.duplicateOfName)}</p>
          ) : null}
        </div>
      </div>
      <Button
        variant="ghost"
        className="staging-row__remove"
        aria-label={cs.correlationStaging.removeNamed(item.fileName)}
        data-testid={`staging-remove-${item.id}`}
        disabled={disabled}
        onClick={() => onRemove(item.id)}
      >
        {cs.correlationStaging.remove}
      </Button>
    </li>
  )
}

function sourceKindLabel(kind: typeof SourceKind.Text | typeof SourceKind.Pcap): string {
  if (kind === SourceKind.Pcap) return cs.correlationStaging.kindPcap
  return cs.correlationStaging.kindText
}

export function focusAfterRemove(focusId: string | null): void {
  if (focusId) {
    const next = document.querySelector<HTMLButtonElement>(`[data-testid="staging-remove-${focusId}"]`)
    if (next) {
      next.focus()
      return
    }
  }
  document.querySelector<HTMLButtonElement>('[data-testid="staging-add-files"]')?.focus()
}
