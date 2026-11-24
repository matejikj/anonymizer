import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { refreshPcapFilter } from './pcapLoadController.ts'
import { getPcapSession } from './pcapSession.ts'
import { getPcapCoverageViewModel } from './getPcapCoverageViewModel.ts'
import { Button } from '../../design-system/index.ts'
import {
  parseDisplayFilter,
  filterSuggestions,
  expressionForChangedOnly,
  expressionForIssueOnly,
  expressionForProtocol,
  expressionForPacketRange,
  combineExpressions,
} from '../displayFilter'

/**
 * Wireshark-like display filter bar (step 2).
 */
export function PcapFilterBar({ compact = false }: { readonly compact?: boolean }) {
  const displayFilterDraft = usePcapStore((s) => s.displayFilterDraft)
  const displayFilterApplied = usePcapStore((s) => s.displayFilterApplied)
  const displayFilterStatus = usePcapStore((s) => s.displayFilterStatus)
  const displayFilterError = usePcapStore((s) => s.displayFilterError)
  const displayFilterHistory = usePcapStore((s) => s.displayFilterHistory)
  const setDisplayFilterDraft = usePcapStore((s) => s.setDisplayFilterDraft)
  const applyDisplayFilter = usePcapStore((s) => s.applyDisplayFilter)
  const clearDisplayFilter = usePcapStore((s) => s.clearDisplayFilter)
  const revertDisplayFilterDraft = usePcapStore((s) => s.revertDisplayFilterDraft)
  const epoch = usePcapStore((s) => s.sessionEpoch)
  const session = epoch >= 0 ? getPcapSession() : null
  const vm = getPcapCoverageViewModel()
  const inputRef = useRef<HTMLInputElement>(null)
  const [builderOpen, setBuilderOpen] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [suggestIndex, setSuggestIndex] = useState(-1)

  const protocols = useMemo(() => {
    if (vm) return vm.protocols.map((p) => p.protocol).sort()
    if (!session?.unifiedCoverage) return []
    return Array.from(session.unifiedCoverage.histogram.keys()).sort()
  }, [session, epoch, vm])

  const suggestions = useMemo(
    () => filterSuggestions(displayFilterDraft),
    [displayFilterDraft],
  )

  const statusClass =
    displayFilterStatus === 'valid'
      ? 'pcap-display-filter--valid'
      : displayFilterStatus === 'incomplete'
        ? 'pcap-display-filter--incomplete'
        : displayFilterStatus === 'invalid'
          ? 'pcap-display-filter--invalid'
          : ''

  const updateDraft = useCallback(
    (value: string) => {
      if (value.length === 0) {
        setDisplayFilterDraft('', 'empty', null)
        return
      }
      const parsed = parseDisplayFilter(value)
      setDisplayFilterDraft(value, parsed.status, parsed.error)
    },
    [setDisplayFilterDraft],
  )

  const doApply = useCallback(() => {
    const parsed = parseDisplayFilter(displayFilterDraft)
    if (parsed.status !== 'valid') return
    applyDisplayFilter(displayFilterDraft.trim())
    setHistoryOpen(false)
    queueMicrotask(() => refreshPcapFilter())
  }, [displayFilterDraft, applyDisplayFilter])

  const doClear = useCallback(() => {
    clearDisplayFilter()
    setHistoryOpen(false)
    queueMicrotask(() => refreshPcapFilter())
  }, [clearDisplayFilter])

  const applySuggestion = (suggestion: string) => {
    const parts = displayFilterDraft.trim().split(/\s+/)
    parts.pop()
    const prefix = parts.length > 0 ? `${parts.join(' ')} ` : ''
    updateDraft(prefix + suggestion)
    setSuggestIndex(-1)
    inputRef.current?.focus()
  }

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') {
      event.preventDefault()
      doApply()
      return
    }
    if (event.key === 'Escape') {
      event.preventDefault()
      revertDisplayFilterDraft()
      setHistoryOpen(false)
      return
    }
    if (suggestions.length > 0) {
      if (event.key === 'ArrowDown') {
        event.preventDefault()
        setSuggestIndex((i) => Math.min(suggestions.length - 1, i + 1))
        return
      }
      if (event.key === 'ArrowUp') {
        event.preventDefault()
        setSuggestIndex((i) => Math.max(-1, i - 1))
        return
      }
      if (event.key === 'Tab' && suggestIndex >= 0) {
        event.preventDefault()
        applySuggestion(suggestions[suggestIndex]!)
        return
      }
    }
  }

  const insertBuilderExpression = (expr: string) => {
    const combined = displayFilterDraft.trim()
      ? combineExpressions([displayFilterApplied || displayFilterDraft, expr])
      : expr
    updateDraft(combined)
    setBuilderOpen(false)
    inputRef.current?.focus()
  }

  useEffect(() => {
    const handler = (event: globalThis.KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === '/') {
        const target = event.target as HTMLElement | null
        if (
          target &&
          (target.tagName === 'INPUT' ||
            target.tagName === 'TEXTAREA' ||
            target.tagName === 'SELECT' ||
            target.isContentEditable ||
            target.closest('[role="dialog"]') ||
            target.closest('[role="tree"]'))
        ) {
          return
        }
        event.preventDefault()
        inputRef.current?.focus()
        inputRef.current?.select()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  return (
    <div
      className={compact ? 'pcap-filter-bar pcap-filter-bar--compact' : 'pcap-filter-bar pcap-filter-bar--display'}
      role="search"
      aria-label={cs.pcap.filter.label}
      data-testid="pcap-filter-bar"
    >
      <div className={`pcap-display-filter ${statusClass}`} data-testid="pcap-display-filter">
        <button
          type="button"
          className="pcap-display-filter__bookmark"
          aria-label={cs.pcap.filter.builderToggle}
          aria-expanded={builderOpen}
          data-testid="pcap-filter-builder-toggle"
          onClick={() => setBuilderOpen((v) => !v)}
        >
          ★
        </button>
        <input
          ref={inputRef}
          type="text"
          className="pcap-display-filter__input"
          value={displayFilterDraft}
          placeholder={cs.pcap.filter.displayPlaceholder}
          spellCheck={false}
          aria-invalid={displayFilterStatus === 'invalid' ? true : undefined}
          aria-describedby={displayFilterError ? 'pcap-filter-error' : undefined}
          data-testid="pcap-display-filter-input"
          onChange={(e) => {
            updateDraft(e.target.value)
            setSuggestIndex(-1)
          }}
          onKeyDown={onKeyDown}
        />
        {displayFilterError ? (
          <span id="pcap-filter-error" className="pcap-display-filter__error" title={displayFilterError.message}>
            {displayFilterError.message}
          </span>
        ) : null}
        <Button variant="ghost" size="tiny" onClick={doClear} data-testid="pcap-filter-clear">
          {cs.pcap.filter.clear}
        </Button>
        <div className="pcap-display-filter__history-wrap">
          <Button
            variant="ghost"
            size="tiny"
            aria-expanded={historyOpen}
            data-testid="pcap-filter-history-toggle"
            onClick={() => setHistoryOpen((v) => !v)}
          >
            {cs.pcap.filter.history}
          </Button>
          {historyOpen && displayFilterHistory.length > 0 ? (
            <ul className="pcap-display-filter__history" data-testid="pcap-filter-history">
              {displayFilterHistory.map((expr) => (
                <li key={expr}>
                  <button
                    type="button"
                    onClick={() => {
                      updateDraft(expr)
                      applyDisplayFilter(expr)
                      setHistoryOpen(false)
                      queueMicrotask(() => refreshPcapFilter())
                    }}
                  >
                    {expr}
                  </button>
                </li>
              ))}
            </ul>
          ) : null}
        </div>
        <Button
          variant="primary"
          size="tiny"
          onClick={doApply}
          disabled={displayFilterStatus === 'invalid' || displayFilterStatus === 'incomplete'}
          data-testid="pcap-filter-apply"
        >
          {cs.pcap.filter.apply}
        </Button>
      </div>

      {suggestions.length > 0 && document.activeElement === inputRef.current ? (
        <ul className="pcap-display-filter__suggestions" data-testid="pcap-filter-suggestions">
          {suggestions.map((s, i) => (
            <li key={s}>
              <button
                type="button"
                className={i === suggestIndex ? 'is-active' : undefined}
                onMouseDown={(e) => {
                  e.preventDefault()
                  applySuggestion(s)
                }}
              >
                {s}
              </button>
            </li>
          ))}
        </ul>
      ) : null}

      {builderOpen ? (
        <div className="pcap-filter-builder" data-testid="pcap-filter-builder">
          <Button variant="ghost" size="tiny" onClick={() => insertBuilderExpression(expressionForChangedOnly())}>
            {cs.pcap.filter.changedOnly}
          </Button>
          <Button variant="ghost" size="tiny" onClick={() => insertBuilderExpression(expressionForIssueOnly())}>
            {cs.pcap.filter.issueOnly}
          </Button>
          {protocols.slice(0, 8).map((p) => (
            <Button
              key={p}
              variant="ghost"
              size="tiny"
              onClick={() => insertBuilderExpression(expressionForProtocol(p))}
            >
              {p}
            </Button>
          ))}
          <label className="pcap-filter-builder__range">
            <span>{cs.pcap.filter.rangeBuilder}</span>
            <input type="number" min={1} id="pcap-filter-range-from" placeholder={cs.pcap.filter.from} />
            <span>–</span>
            <input type="number" min={1} id="pcap-filter-range-to" placeholder={cs.pcap.filter.to} />
            <Button
              variant="ghost"
              size="tiny"
              onClick={() => {
                const fromEl = document.getElementById('pcap-filter-range-from') as HTMLInputElement | null
                const toEl = document.getElementById('pcap-filter-range-to') as HTMLInputElement | null
                const from = fromEl?.value ? Number(fromEl.value) : null
                const to = toEl?.value ? Number(toEl.value) : null
                insertBuilderExpression(expressionForPacketRange(from, to))
              }}
            >
              {cs.pcap.filter.insertRange}
            </Button>
          </label>
        </div>
      ) : null}

      {displayFilterApplied ? (
        <p className="pcap-display-filter__applied" data-testid="pcap-filter-applied">
          {cs.pcap.filter.applied.replace('{expr}', displayFilterApplied)}
        </p>
      ) : null}
    </div>
  )
}
