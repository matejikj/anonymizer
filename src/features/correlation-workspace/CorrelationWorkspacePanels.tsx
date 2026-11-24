import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react'
import { cs } from '../../i18n/cs.ts'
import { useAppStore } from '../../app/store.ts'
import { FileKindBadge } from '../../components/ui/FileKindBadge.tsx'
import { StatusChip } from '../../components/ui/StatusChip.tsx'
import type { SourceKind } from '../../domain/sourceArtifact.ts'
import {
  buildCorrelationEntityRows,
  buildCrossFormatSharedCategoryCounts,
  getCorrelationWorkspaceSummary,
  getEntityListMode,
  isOriginalRevealed,
  isMultiSourceCorrelationReview,
  setEntityListMode,
  setOriginalRevealed,
  sourceStatusLabel,
} from '../../correlation/correlationReviewModel.ts'
import {
  jumpToCorrelationOccurrence,
  selectCorrelationSourceWithAnnounce,
} from '../../correlation/correlationWorkspaceController.ts'
import { listCorrelationSources } from '../../correlation/correlationSessionModel.ts'
import { formatBytes } from '../../pcap/ui/formatters.ts'
import { identityCategoryLabel } from '../resolve-only/identityCategoryLabel.ts'
import { rovingKeyNavigate } from './rovingKeyNavigate.ts'
import { IconArrow, IconDiamond, IconPlus, IconX } from '../../components/ui/icons.tsx'
import { Button, IconButton } from '../../design-system/index.ts'
import { removeCorrelationSource } from '../../correlation/correlationController.ts'

interface SourceInfo {
  readonly fileName: string
  readonly kind: SourceKind
}

function sourceInfoById(): Map<string, SourceInfo> {
  return new Map(listCorrelationSources().map((s) => [s.sourceId, { fileName: s.fileName, kind: s.kind }]))
}

function sourceTone(sourceId: string): 'ok' | 'warn' | 'error' {
  const source = listCorrelationSources().find((s) => s.sourceId === sourceId)
  if (!source) return 'warn'
  if (source.phase === 'failed') return 'error'
  if (source.phase === 'planned' && source.exportState === 'ready') return 'ok'
  return 'warn'
}

export function SourceRail(props: {
  readonly onAddClick?: () => void
  readonly addBusy?: boolean
  readonly onCancelAdd?: () => void
}) {
  void useAppStore((s) => s.correlationEpoch)
  const selected = useAppStore((s) => s.selectedCorrelationSourceId)
  const sources = listCorrelationSources()
  const items: Array<'all' | string> = ['all', ...sources.map((s) => s.sourceId)]
  const activeIndex = Math.max(0, items.indexOf(selected))
  const buttonRefs = useRef<Array<HTMLButtonElement | null>>([])
  const selectId = useId()

  useEffect(() => {
    buttonRefs.current[activeIndex]?.focus()
  }, [activeIndex, selected])

  const onKeyDown = (event: KeyboardEvent, index: number) => {
    rovingKeyNavigate(event, {
      itemCount: items.length,
      activeIndex: index,
      onActivate: (next) => {
        const id = items[next]!
        selectCorrelationSourceWithAnnounce(id)
        queueMicrotask(() => buttonRefs.current[next]?.focus())
      },
      onSelect: (next) => {
        selectCorrelationSourceWithAnnounce(items[next]!)
      },
    })
  }

  return (
    <div className="corr-rail-host" data-testid="correlation-source-bar-host">
      <nav className="corr-rail corr-rail--horizontal" aria-label={cs.correlationWorkspace.sourcesNav}>
        <ul
          className="corr-rail__list"
          role="listbox"
          aria-orientation="horizontal"
          aria-label={cs.correlationWorkspace.sourcesNav}
          data-testid="correlation-source-rail"
        >
          {items.map((id, index) => {
            const isAll = id === 'all'
            const source = isAll ? null : sources.find((s) => s.sourceId === id)
            const label = isAll ? cs.correlationWorkspace.setOverview : source!.fileName
            const selectedHere = selected === id
            return (
              <li key={id} role="presentation" className="corr-rail__slot">
                <button
                  ref={(el) => {
                    buttonRefs.current[index] = el
                  }}
                  type="button"
                  role="option"
                  aria-selected={selectedHere}
                  tabIndex={selectedHere ? 0 : -1}
                  className={`corr-rail__item${selectedHere ? ' corr-rail__item--active' : ''}`}
                  aria-label={isAll ? label : `${label}, ${sourceStatusLabel(source!)}`}
                  title={isAll ? label : source!.fileName}
                  data-testid={isAll ? 'corr-rail-all' : `corr-rail-${id}`}
                  onClick={() => selectCorrelationSourceWithAnnounce(id)}
                  onKeyDown={(e) => onKeyDown(e, index)}
                >
                  {isAll ? (
                    <span className="corr-rail__name">{cs.correlationWorkspace.setOverview}</span>
                  ) : (
                    <>
                      <FileKindBadge kind={source!.kind} />
                      <span className="corr-rail__name" title={source!.fileName}>
                        {source!.fileName}
                      </span>
                      <StatusChip
                        tone={sourceTone(id)}
                        label={sourceStatusLabel(source!)}
                        compact
                      />
                    </>
                  )}
                </button>
              </li>
            )
          })}
        </ul>
      </nav>

      <label className="corr-rail-select-wrap" htmlFor={selectId}>
        <span className="visually-hidden">{cs.correlationWorkspace.sourceSelectLabel}</span>
        <select
          id={selectId}
          className="corr-rail-select"
          data-testid="correlation-source-select"
          value={selected}
          aria-label={cs.correlationWorkspace.sourceSelectLabel}
          onChange={(e) => {
            const value = e.target.value
            selectCorrelationSourceWithAnnounce(value === 'all' ? 'all' : value)
          }}
        >
          <option value="all">{cs.correlationWorkspace.setOverview}</option>
          {sources.map((s) => (
            <option key={s.sourceId} value={s.sourceId} title={s.fileName}>
              {s.fileName}
            </option>
          ))}
        </select>
      </label>

      <div className="corr-rail-add">
        {props.addBusy ? (
          <IconButton
            label={cs.correlationWorkspace.cancelAddSource}
            data-testid="correlation-add-source-cancel"
            onClick={props.onCancelAdd}
          >
            <IconX size={18} />
          </IconButton>
        ) : (
          <IconButton
            label={cs.correlationWorkspace.addSource}
            data-testid="correlation-add-source"
            onClick={props.onAddClick}
          >
            <IconPlus size={18} />
          </IconButton>
        )}
      </div>
    </div>
  )
}

export function SourceOverview() {
  void useAppStore((s) => s.correlationEpoch)
  const sources = listCorrelationSources()
  const summary = getCorrelationWorkspaceSummary()
  const sharedCount = buildCorrelationEntityRows('shared').length
  const sharedByCategory = buildCrossFormatSharedCategoryCounts()
  const allReady = summary.reviewCount === 0
  const showSharedList = isMultiSourceCorrelationReview() && sharedCount > 0
  const [removingId, setRemovingId] = useState<string | null>(null)

  const onRemove = async (sourceId: string) => {
    setRemovingId(sourceId)
    try {
      const result = await removeCorrelationSource(sourceId)
      if (!('ok' in result) || !result.ok) {
        useAppStore.getState().setToast({
          message: 'message' in result ? result.message : cs.correlationWorkspace.removeSourceFailed,
        })
        return
      }
      const remaining = listCorrelationSources()
      if (remaining.length === 0) {
        selectCorrelationSourceWithAnnounce('all')
      } else if (useAppStore.getState().selectedCorrelationSourceId === sourceId) {
        selectCorrelationSourceWithAnnounce(remaining[0]!.sourceId)
      }
    } finally {
      setRemovingId(null)
    }
  }

  return (
    <section className="corr-overview corr-overview--compact" data-testid="correlation-source-overview">
      <header className="corr-overview__head">
        <div>
          <h2 className="corr-overview__title type-section-title">{cs.correlationWorkspace.overviewTitle}</h2>
        </div>
        <StatusChip
          tone={allReady ? 'ok' : 'warn'}
          label={allReady ? cs.correlationWorkspace.toolbarReady(true) : cs.correlationWorkspace.toolbarReady(false)}
          testId="corr-overview-status"
        />
      </header>

      <ul className="corr-overview__stats" aria-label={cs.correlationWorkspace.overviewStatsLabel}>
        <li>
          <strong>{sources.length}</strong> {cs.correlationWorkspace.overviewStatFiles}
        </li>
        <li>
          <strong>{sharedCount}</strong> {cs.correlationWorkspace.overviewStatShared}
        </li>
        <li>
          <strong>{summary.readyCount}</strong> {cs.correlationWorkspace.overviewStatReady}
        </li>
      </ul>

      {sharedByCategory.length > 0 ? (
        <ul
          className="corr-overview__cf-stats"
          aria-label={cs.correlationWorkspace.overviewSharedByCategory}
          data-testid="correlation-shared-by-category"
        >
          {sharedByCategory.map(({ category, count }) => (
            <li key={category}>{cs.correlationWorkspace.overviewCfCategory(category, count)}</li>
          ))}
        </ul>
      ) : null}

      <ul className="corr-overview__list" data-testid="correlation-overview-list">
        {sources.map((source) => {
          const ready = source.phase === 'planned' && source.exportState === 'ready'
          return (
            <li key={source.sourceId} className="corr-overview__row">
              <button
                type="button"
                className="corr-overview__row-main"
                data-testid={`corr-overview-card-${source.sourceId}`}
                onClick={() => selectCorrelationSourceWithAnnounce(source.sourceId)}
              >
                <FileKindBadge kind={source.kind} />
                <span className="corr-overview__name" title={source.fileName}>
                  {source.fileName}
                </span>
                <span className="corr-overview__meta">{formatBytes(source.byteLength)}</span>
                <StatusChip
                  tone={ready ? 'ok' : source.phase === 'failed' ? 'error' : 'warn'}
                  label={sourceStatusLabel(source)}
                />
              </button>
              <Button
                variant="ghost"
                data-testid={`corr-remove-source-${source.sourceId}`}
                disabled={removingId === source.sourceId}
                aria-label={cs.correlationWorkspace.removeSourceNamed(source.fileName)}
                onClick={() => void onRemove(source.sourceId)}
              >
                {cs.correlationWorkspace.removeSource}
              </Button>
            </li>
          )
        })}
      </ul>

      {sharedCount === 0 ? (
        <div className="corr-overview__empty-shared" data-testid="correlation-no-shared" role="status">
          <IconDiamond size={16} className="corr-overview__empty-icon" aria-hidden />
          <p className="corr-overview__stat">{cs.correlationWorkspace.noSharedValues}</p>
        </div>
      ) : null}

      {showSharedList ? (
        <div className="corr-overview__shared">
          <SharedEntityList embedded />
        </div>
      ) : null}
    </section>
  )
}

export function EmptySetPanel(props: {
  readonly onAddClick: () => void
  readonly onClose: () => void
}) {
  return (
    <section className="corr-empty-set" data-testid="correlation-empty-set">
      <h2 className="type-page-title">{cs.correlationWorkspace.emptySetTitle}</h2>
      <p className="type-meta">{cs.correlationWorkspace.emptySetBody}</p>
      <div className="corr-empty-set__actions">
        <Button variant="primary" data-testid="correlation-empty-add" onClick={props.onAddClick}>
          {cs.correlationWorkspace.emptySetAdd}
        </Button>
        <Button variant="secondary" data-testid="correlation-empty-close" onClick={props.onClose}>
          {cs.correlationWorkspace.close}
        </Button>
      </div>
    </section>
  )
}

export interface SharedEntityListProps {
  readonly embedded?: boolean
}

export function SharedEntityList({ embedded = false }: SharedEntityListProps) {
  const correlationEpoch = useAppStore((s) => s.correlationEpoch)
  const mode = getEntityListMode()
  const [showOriginal, setShowOriginal] = useState(() => isOriginalRevealed())
  const rows = buildCorrelationEntityRows(mode)
  const sourceInfo = sourceInfoById()
  const [activeIndex, setActiveIndex] = useState(0)
  const buttonRefs = useRef<Array<HTMLButtonElement | null>>([])

  useEffect(() => {
    setShowOriginal(isOriginalRevealed())
  }, [correlationEpoch])

  useEffect(() => {
    setActiveIndex(0)
  }, [mode, rows.length])

  const onKeyDown = (event: KeyboardEvent, index: number) => {
    rovingKeyNavigate(event, {
      itemCount: rows.length,
      activeIndex: index,
      onActivate: (next) => {
        setActiveIndex(next)
        queueMicrotask(() => buttonRefs.current[next]?.focus())
      },
      onSelect: (next) => {
        const first = rows[next]?.occurrences[0]
        if (first) jumpToCorrelationOccurrence(first)
      },
    })
  }

  return (
    <div
      className={embedded ? 'corr-entities corr-entities--embedded' : 'corr-entities'}
      aria-label={cs.correlationWorkspace.entitiesPanel}
    >
      <div className="corr-entities__head">
        <div>
          <h3 className="corr-entities__title type-section-title">{cs.correlationWorkspace.entitiesPanel}</h3>
        </div>
        <div className="corr-entities__tabs" role="tablist" aria-label={cs.correlationWorkspace.entitiesPanel}>
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'shared'}
            className={mode === 'shared' ? 'corr-entities__tab corr-entities__tab--active' : 'corr-entities__tab'}
            data-testid="corr-entities-tab-shared"
            onClick={() => setEntityListMode('shared')}
          >
            {cs.correlationWorkspace.tabShared}
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'all'}
            className={mode === 'all' ? 'corr-entities__tab corr-entities__tab--active' : 'corr-entities__tab'}
            data-testid="corr-entities-tab-all"
            onClick={() => setEntityListMode('all')}
          >
            {cs.correlationWorkspace.tabAll}
          </button>
        </div>
      </div>

      <div className="corr-entities__toolbar">
        <Button
          variant="ghost"
          className="corr-entities__reveal"
          data-testid="corr-entities-reveal-toggle"
          onClick={() => {
            const next = !showOriginal
            setShowOriginal(next)
            setOriginalRevealed(next)
          }}
        >
          {showOriginal ? cs.correlationWorkspace.hideOriginal : cs.correlationWorkspace.showOriginal}
        </Button>
      </div>
      {rows.length === 0 ? (
        <p className="corr-entities__empty" role="status" data-testid="corr-entities-empty">
          {mode === 'shared'
            ? cs.correlationWorkspace.noSharedValues
            : cs.review.noFindings}
        </p>
      ) : (
        <ul
          className="corr-entities__list"
          role="listbox"
          aria-label={cs.correlationWorkspace.entitiesPanel}
          data-testid="correlation-entity-list"
        >
          {rows.map((row, index) => {
            const categoryLabel = identityCategoryLabel(row.category)
            const originalDisplay = showOriginal ? row.original : row.maskedOriginal
            const sourceNames = row.sourceIds
              .map((id) => sourceInfo.get(id)?.fileName)
              .filter((name): name is string => Boolean(name))
              .join(', ')
            return (
              <li
                key={row.key}
                className="corr-entities__row"
                role="presentation"
                data-testid={`corr-entity-${row.key}`}
              >
                <article className="corr-entities__card">
                  <button
                    ref={(el) => {
                      buttonRefs.current[index] = el
                    }}
                    type="button"
                    role="option"
                    aria-selected={index === activeIndex}
                    tabIndex={index === activeIndex ? 0 : -1}
                    className="corr-entities__primary"
                    aria-label={cs.correlationWorkspace.entityLabel(row.alias, categoryLabel, sourceNames)}
                    data-testid={`corr-entity-jump-${row.key}`}
                    onClick={() => {
                      setActiveIndex(index)
                      const first = row.occurrences[0]
                      if (first) jumpToCorrelationOccurrence(first)
                    }}
                    onKeyDown={(e) => onKeyDown(e, index)}
                  >
                    <span className="corr-entities__category">{categoryLabel}</span>
                    <div className="corr-entities__mapping">
                      <span className="corr-entities__original">{originalDisplay}</span>
                      <span className="corr-entities__arrow" aria-hidden="true">
                        <IconArrow size={16} />
                      </span>
                      <span className="corr-entities__alias">{row.alias}</span>
                    </div>
                  </button>
                  <div className="corr-entities__sources">
                    <span className="corr-entities__sources-label">{cs.correlationWorkspace.openInFiles}</span>
                    {row.sourceIds.map((sourceId) => {
                      const source = sourceInfo.get(sourceId)
                      if (!source) return null
                      const occurrence = row.occurrences.find((o) => o.sourceId === sourceId)
                      return (
                        <button
                          key={sourceId}
                          type="button"
                          className="corr-entities__source-chip"
                          data-testid={`corr-entity-source-${row.key}--${sourceId}`}
                          disabled={!occurrence}
                          title={
                            occurrence
                              ? cs.correlationWorkspace.jumpToSource(source.fileName, row.alias)
                              : undefined
                          }
                          aria-label={cs.correlationWorkspace.jumpToSource(source.fileName, row.alias)}
                          onClick={() => {
                            setActiveIndex(index)
                            if (occurrence) jumpToCorrelationOccurrence(occurrence)
                          }}
                        >
                          <FileKindBadge kind={source.kind} />
                          <span className="corr-entities__source-name">{source.fileName}</span>
                        </button>
                      )
                    })}
                  </div>
                </article>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
