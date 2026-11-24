/**
 * Browsable, searchable table of every entry in an imported mapping bundle (Stage 30 redesign).
 * Lets a user find an original value either by pasting the alias they saw in an AI answer,
 * or by browsing/filtering by category — no separate "exact lookup" tool needed, since typing
 * an alias into the search box already narrows the table to the matching row(s).
 */

import { useMemo, useState } from 'react'
import type { IdentityCategory } from '../../mapping/identityCategories.ts'
import type { MappingBundlePayload } from '../../mapping/bundle/types.ts'
import { cs } from '../../i18n/cs.ts'
import { Button } from '../../design-system/index.ts'
import { IconSearch } from '../../components/ui/icons.tsx'
import { identityCategoryLabel } from './identityCategoryLabel.ts'
import { MaskedOriginal } from './MaskedOriginal.tsx'

const PAGE_SIZE = 50
const MAX_VISIBLE = 2000

export function MappingBundleBrowser(props: { payload: MappingBundlePayload }) {
  const { payload } = props
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState<IdentityCategory | 'all'>('all')
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE)

  const categoryCounts = useMemo(() => {
    const counts = new Map<IdentityCategory, number>()
    for (const entry of payload.entries) {
      counts.set(entry.category, (counts.get(entry.category) ?? 0) + 1)
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1])
  }, [payload.entries])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    let list = payload.entries
    if (category !== 'all') list = list.filter((e) => e.category === category)
    if (q) {
      list = list.filter(
        (e) => e.alias.toLowerCase().includes(q) || e.canonical.toLowerCase().includes(q),
      )
    }
    return [...list].sort((a, b) => b.occurrenceCount - a.occurrenceCount)
  }, [payload.entries, query, category])

  const visible = filtered.slice(0, visibleCount)
  const hasMore = filtered.length > visible.length && visibleCount < MAX_VISIBLE

  function setQueryAndReset(value: string): void {
    setQuery(value)
    setVisibleCount(PAGE_SIZE)
  }

  function setCategoryAndReset(value: IdentityCategory | 'all'): void {
    setCategory(value)
    setVisibleCount(PAGE_SIZE)
  }

  if (payload.entries.length === 0) {
    return (
      <section className="mapping-browse" data-testid="mapping-browse">
        <h2 className="type-section-title">{cs.resolveReturn.browseTitle}</h2>
        <p className="mapping-browse__empty" data-testid="mapping-browse-empty">
          {cs.resolveReturn.browseEmptyNoEntries}
        </p>
      </section>
    )
  }

  return (
    <section className="mapping-browse" data-testid="mapping-browse">
      <h2 className="type-section-title">{cs.resolveReturn.browseTitle}</h2>

      <label className="mapping-browse__search" htmlFor="mapping-browse-search-input">
        <IconSearch size={16} className="mapping-browse__search-icon" />
        <span className="visually-hidden">{cs.resolveReturn.browseSearchLabel}</span>
        <input
          id="mapping-browse-search-input"
          type="search"
          data-testid="mapping-browse-search"
          placeholder={cs.resolveReturn.browseSearchPlaceholder}
          value={query}
          onChange={(e) => setQueryAndReset(e.target.value)}
        />
      </label>

      <div
        className="mapping-browse__chips"
        role="group"
        aria-label={cs.resolveReturn.browseCategoryLabel}
      >
        <button
          type="button"
          className={`mapping-browse__chip${category === 'all' ? ' is-active' : ''}`}
          aria-pressed={category === 'all'}
          data-testid="mapping-browse-chip-all"
          onClick={() => setCategoryAndReset('all')}
        >
          {cs.resolveReturn.browseAllCategories}
          <span className="mapping-browse__chip-count">{payload.entries.length}</span>
        </button>
        {categoryCounts.map(([cat, count]) => (
          <button
            key={cat}
            type="button"
            className={`mapping-browse__chip${category === cat ? ' is-active' : ''}`}
            aria-pressed={category === cat}
            data-testid={`mapping-browse-chip-${cat}`}
            onClick={() => setCategoryAndReset(cat)}
          >
            {identityCategoryLabel(cat)}
            <span className="mapping-browse__chip-count">{count}</span>
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <p className="mapping-browse__empty" data-testid="mapping-browse-empty">
          {cs.resolveReturn.browseEmpty}
        </p>
      ) : (
        <>
          <div className="mapping-browse__table-wrap">
            <table className="mapping-browse__table" data-testid="mapping-browse-table">
              <thead>
                <tr>
                  <th scope="col">{cs.resolveReturn.colCategory}</th>
                  <th scope="col">{cs.resolveReturn.colAlias}</th>
                  <th scope="col">{cs.resolveReturn.colOriginal}</th>
                  <th scope="col" className="mapping-browse__col-num">{cs.resolveReturn.colOccurrences}</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((entry) => (
                  <tr key={entry.identityId} data-testid="mapping-browse-row">
                    <td>
                      <span className="mapping-browse__category">{identityCategoryLabel(entry.category)}</span>
                    </td>
                    <td>
                      <code className="mapping-browse__alias" data-testid="mapping-browse-alias">{entry.alias}</code>
                      {entry.disposition === 'ambiguous-fixed' ? (
                        <span className="badge badge--warn">{cs.resolveReturn.dispositionAmbiguous}</span>
                      ) : null}
                      {entry.disposition === 'preserved' ? (
                        <span className="badge">{cs.resolveReturn.dispositionPreserved}</span>
                      ) : null}
                    </td>
                    <td>
                      <MaskedOriginal value={entry.canonical} testId={`mapping-browse-original-${entry.identityId}`} />
                    </td>
                    <td className="mapping-browse__col-num">{entry.occurrenceCount}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mapping-browse__footer">
            <p className="mapping-browse__count" data-testid="mapping-browse-count">
              {cs.resolveReturn.browseShowing
                .replace('{shown}', String(visible.length))
                .replace('{total}', String(filtered.length))}
            </p>
            {hasMore ? (
              <Button
                variant="secondary"
                data-testid="mapping-browse-more"
                onClick={() => setVisibleCount((n) => Math.min(n + PAGE_SIZE, MAX_VISIBLE))}
              >
                {cs.resolveReturn.browseLoadMore}
              </Button>
            ) : null}
          </div>
        </>
      )}
    </section>
  )
}
