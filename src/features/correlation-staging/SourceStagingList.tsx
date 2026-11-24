import { cs } from '../../i18n/cs.ts'
import { formatStagingSize } from '../../correlation/import/stagingModel.ts'
import type { StagingBatchSummary, StagingItem } from '../../correlation/import/types.ts'
import { SourceStagingRow } from './SourceStagingRow.tsx'

export interface SourceStagingListProps {
  readonly items: readonly StagingItem[]
  readonly summary: StagingBatchSummary
  readonly onRemove: (id: string) => void
}

export function SourceStagingList({ items, summary, onRemove }: SourceStagingListProps) {
  const highlightIds = new Set(summary.aggregateOverLimit ? summary.largestReadyIds : [])

  return (
    <section className="staging-list" aria-labelledby="staging-list-title">
      <header className="staging-list__header">
        <h2 id="staging-list-title" className="type-page-title">
          {cs.correlationStaging.title}
        </h2>
        <p className="staging-list__summary type-meta">
          {cs.correlationStaging.summary(summary.readyCount, formatStagingSize(summary.totalBytes))}
        </p>
        {summary.aggregateOverLimit && summary.bytesToRemove != null ? (
          <p className="staging-list__limit" role="alert" data-testid="staging-aggregate-limit">
            {cs.correlationStaging.aggregateLimit(
              formatStagingSize(summary.totalBytes),
              formatStagingSize(summary.aggregateLimitBytes),
              formatStagingSize(summary.bytesToRemove),
            )}
          </p>
        ) : null}
      </header>
      <ul className="staging-list__items" data-testid="staging-source-list">
        {items.map((item) => (
          <SourceStagingRow
            key={item.id}
            item={item}
            highlighted={highlightIds.has(item.id)}
            onRemove={onRemove}
          />
        ))}
      </ul>
    </section>
  )
}
