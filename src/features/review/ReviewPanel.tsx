import { useMemo, useRef, useState, useEffect } from 'react'
import type { Category, EntitySummary } from '../../domain/types.ts'
import { useAppStore } from '../../app/store.ts'
import { getSessionModel } from '../workspace/sessionModel.ts'
import {
  summarizeCategories,
  isEffectivelyEnabled,
  type CategoryMasterMap,
} from './entityState.ts'
import { CATEGORY_LABELS } from './categoryLabels.ts'
import {
  actionJumpToEntity,
  actionToggleCategory,
  actionToggleEntity,
} from './reviewActions.ts'
import { CustomRulesPanel } from '../rules/CustomRulesPanel.tsx'
import { SharedEntityList } from '../correlation-workspace/CorrelationWorkspacePanels.tsx'
import { isMultiSourceCorrelationReview } from '../../correlation/correlationReviewModel.ts'
import { cs } from '../../i18n/cs.ts'
import { IconArrow } from '../../components/ui/icons.tsx'
import { Button } from '../../design-system/index.ts'

const ROW_HEIGHT = 44
const VIRTUALIZE_AFTER = 200

export function ReviewPanel({ correlationSourceId }: { readonly correlationSourceId?: string } = {}) {
  const sessionEpoch = useAppStore((s) => s.sessionEpoch)
  const phase = useAppStore((s) => s.phase)
  const tab = useAppStore((s) => s.reviewTab)
  const filter = useAppStore((s) => s.entityFilter)
  const query = useAppStore((s) => s.entityQuery)
  const planBusy = useAppStore((s) => s.planBusy)
  const importProgress = useAppStore((s) => s.importProgress)
  const showSharedTab =
    (phase === 'correlation-review' || Boolean(correlationSourceId)) &&
    isMultiSourceCorrelationReview()
  const session = sessionEpoch >= 0 ? getSessionModel() : null
  const recomputePct =
    planBusy && importProgress.totalBytes && importProgress.totalBytes > 0
      ? Math.min(100, Math.round((importProgress.processedBytes / importProgress.totalBytes) * 100))
      : null

  const categories = useMemo(() => {
    const s = getSessionModel()
    if (!s) return []
    return summarizeCategories(s.entities, s.categoryMasters)
  }, [sessionEpoch])

  const overviewCounts = useMemo(() => {
    if (!session) return { found: 0, replaced: 0, kept: 0 }
    let replaced = 0
    let kept = 0
    for (const e of session.entities) {
      if (isEffectivelyEnabled(e, session.categoryMasters)) replaced += 1
      else kept += 1
    }
    return { found: session.entities.length, replaced, kept }
  }, [session, sessionEpoch])

  if (!session) return null

  return (
    <aside
      className="review-panel"
      aria-label={cs.review.title}
      data-testid="review-panel"
      data-correlation-source={correlationSourceId || undefined}
    >
      <header className="review-panel__header">
        <h2>{cs.review.title}</h2>
        {planBusy ? (
          <span className="review-panel__busy" data-testid="plan-busy-indicator">
            <span className="spinner" aria-hidden="true" />
            {cs.review.recomputing}
            {recomputePct != null ? ` ${recomputePct} %` : ''}
          </span>
        ) : null}
      </header>
      <div className="review-tabs" role="tablist" aria-label={cs.review.tabsLabel}>
        {(
          [
            ['overview', cs.review.tabOverview],
            ['entities', cs.review.tabEntities],
            ['rules', cs.review.tabRules],
            ...(showSharedTab ? [['shared', cs.review.tabShared] as const] : []),
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={tab === id}
            className={tab === id ? 'review-tabs__btn is-active' : 'review-tabs__btn'}
            data-testid={`review-tab-${id}`}
            onClick={() => useAppStore.getState().setReviewTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'overview' ? (
        <div className="review-panel__body" role="tabpanel" data-testid="review-overview">
          <p className="review-panel__overview-lead" data-testid="review-overview-counts">
            {cs.review.overviewCounts
              .replace('{found}', String(overviewCounts.found))
              .replace('{replaced}', String(overviewCounts.replaced))
              .replace('{kept}', String(overviewCounts.kept))}
          </p>
          <ul className="category-list">
            {categories.map((row) => {
              const replacedInCat = row.masterEnabled ? row.enabledUnique : 0
              const keptInCat = row.uniqueCount - replacedInCat
              return (
                <li key={row.category} className="category-list__row">
                  <div className="category-list__meta">
                    <strong>{CATEGORY_LABELS[row.category]}</strong>
                    <span>
                      {cs.review.categoryCounts
                        .replace('{found}', String(row.uniqueCount))
                        .replace('{replaced}', String(replacedInCat))
                        .replace('{kept}', String(keptInCat))
                        .replace('{occs}', String(row.occurrenceCount))}
                    </span>
                    {row.partiallyDisabled ? (
                      <span className="category-list__hint">{cs.review.partialOff}</span>
                    ) : null}
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={row.masterEnabled}
                      data-testid={`category-switch-${row.category}`}
                      aria-label={`${cs.review.masterSwitch}: ${CATEGORY_LABELS[row.category]}`}
                      onChange={(e) => {
                        useAppStore.getState().setPlanBusy(true)
                        void actionToggleCategory(row.category, e.target.checked).finally(() => {
                          useAppStore.getState().setPlanBusy(false)
                        })
                      }}
                    />
                    <span />
                  </label>
                </li>
              )
            })}
          </ul>
          {categories.length === 0 ? (
            <div className="review-empty" data-testid="review-no-findings">
              <p>{cs.review.noFindings}</p>
              <Button
                variant="secondary"
                data-testid="review-add-rule-cta"
                onClick={() => useAppStore.getState().setReviewTab('rules')}
              >
                {cs.review.addRuleCta}
              </Button>
            </div>
          ) : null}
        </div>
      ) : null}

      {tab === 'entities' ? (
        <div className="review-panel__body" role="tabpanel" data-testid="review-entities">
          <div className="entity-filters">
            <label className="entity-filters__search">
              <span className="visually-hidden">{cs.review.search}</span>
              <input
                type="search"
                value={query}
                placeholder={cs.review.searchPlaceholder}
                data-testid="entity-search"
                onChange={(e) => useAppStore.getState().setEntityQuery(e.target.value)}
              />
            </label>
            <label className="entity-filters__select">
              <span className="visually-hidden">{cs.review.filterCategory}</span>
              <select
                value={filter}
                data-testid="entity-filter"
                onChange={(e) =>
                  useAppStore
                    .getState()
                    .setEntityFilter(e.target.value as 'all' | Category)
                }
              >
                <option value="all">{cs.review.allCategories}</option>
                {categories.map((c) => (
                  <option key={c.category} value={c.category}>
                    {CATEGORY_LABELS[c.category]}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <EntityVirtualList
            entities={session.entitySummaries}
            masters={session.categoryMasters}
            filter={filter}
            query={query}
            sessionEpoch={sessionEpoch}
          />
        </div>
      ) : null}

      {tab === 'rules' ? (
        <div className="review-panel__body" role="tabpanel" data-testid="review-rules">
          <CustomRulesPanel />
        </div>
      ) : null}

      {tab === 'shared' && showSharedTab ? (
        <div className="review-panel__body" role="tabpanel" data-testid="review-shared">
          <SharedEntityList embedded />
        </div>
      ) : null}
    </aside>
  )
}

function EntityVirtualList(props: {
  entities: EntitySummary[]
  masters: CategoryMasterMap
  filter: 'all' | Category
  query: string
  sessionEpoch: number
}) {
  const filtered = useMemo(() => {
    const q = props.query.trim().toLowerCase()
    return props.entities.filter((e) => {
      if (props.filter !== 'all' && e.category !== props.filter) return false
      if (!q) return true
      return (
        e.originalSample.toLowerCase().includes(q) ||
        e.replacement.toLowerCase().includes(q) ||
        e.normalized.toLowerCase().includes(q) ||
        CATEGORY_LABELS[e.category].toLowerCase().includes(q)
      )
    })
  }, [props.entities, props.filter, props.query, props.sessionEpoch])

  const scrollRef = useRef<HTMLDivElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [viewportH, setViewportH] = useState(320)

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const ro = new ResizeObserver(() => setViewportH(el.clientHeight))
    ro.observe(el)
    setViewportH(el.clientHeight)
    return () => ro.disconnect()
  }, [])

  const virtualize = filtered.length >= VIRTUALIZE_AFTER
  const totalH = filtered.length * ROW_HEIGHT
  const start = virtualize ? Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - 4) : 0
  const visibleCount = virtualize
    ? Math.ceil(viewportH / ROW_HEIGHT) + 8
    : filtered.length
  const end = Math.min(filtered.length, start + visibleCount)
  const slice = filtered.slice(start, end)

  return (
    <div
      className="entity-list"
      ref={scrollRef}
      data-testid="entity-list"
      onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}
    >
      <div style={virtualize ? { height: totalH, position: 'relative' } : undefined}>
        {slice.map((entity, i) => {
          const index = start + i
          const effective = isEffectivelyEnabled(entity, props.masters)
          const categoryOff = !props.masters[entity.category]
          return (
            <div
              key={entity.key}
              className={
                effective ? 'entity-list__row' : 'entity-list__row entity-list__row--off'
              }
              style={
                virtualize
                  ? {
                      position: 'absolute',
                      top: index * ROW_HEIGHT,
                      left: 0,
                      right: 0,
                      height: ROW_HEIGHT,
                    }
                  : undefined
              }
              data-testid={`entity-row-${entity.key}`}
            >
              <button
                type="button"
                className="entity-list__jump"
                onClick={() => actionJumpToEntity(entity.key)}
                title={cs.review.jumpToFirst}
              >
                <span className="entity-list__sample">{entity.originalSample}</span>
                <span className="entity-list__arrow" aria-hidden>
                  <IconArrow size={16} />
                </span>
                <span className="entity-list__replacement">{entity.replacement}</span>
                <span className="entity-list__count">
                  {entity.occurrenceCount}× · {CATEGORY_LABELS[entity.category]}
                  {effective
                    ? ` · ${cs.review.valueReplaced}`
                    : ` · ${cs.review.valueKept}`}
                </span>
              </button>
              <label
                className="switch"
                title={categoryOff ? cs.review.entityBlockedByCategory : undefined}
              >
                <input
                  type="checkbox"
                  checked={entity.enabled}
                  disabled={categoryOff}
                  data-testid={`entity-switch-${entity.key}`}
                  aria-label={`${cs.review.entitySwitch}: ${entity.originalSample}`}
                  aria-disabled={categoryOff || undefined}
                  aria-description={categoryOff ? cs.review.entityBlockedByCategory : undefined}
                  onChange={(e) => actionToggleEntity(entity.key, e.target.checked)}
                />
                <span />
              </label>
            </div>
          )
        })}
      </div>
      {filtered.length === 0 ? <p className="review-empty">{cs.review.noMatchFilter}</p> : null}
    </div>
  )
}
