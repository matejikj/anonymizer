import { useEffect, useRef, useState, type RefObject } from 'react'
import { Compartment, EditorState, EditorSelection, type Text } from '@codemirror/state'
import {
  EditorView,
  keymap,
  lineNumbers,
  drawSelection,
  highlightActiveLine,
  highlightActiveLineGutter,
} from '@codemirror/view'
import { defaultKeymap } from '@codemirror/commands'
import { searchKeymap, highlightSelectionMatches, SearchCursor } from '@codemirror/search'
import { getSessionModel } from './sessionModel.ts'
import {
  createAnonymizedViewportPlugin,
  createAnonymizedSecurityExtensions,
  createOriginalMatchHighlightPlugin,
  refreshAnonEffect,
} from './AnonymizedViewport.ts'
import {
  attachSynchronizedEditors,
  scrollToPhysicalLine,
  topVisibleLine,
  type SyncControllers,
} from './useSynchronizedEditors.ts'
import { registerDualLogBridge } from './editorBridge.ts'
import {
  highlightField,
  dispatchHighlight,
  setHighlightEffect,
  clearHighlight,
} from './syncHighlight.ts'
import { findAnonymizedMatches } from './anonymizedSearch.ts'
import {
  createSearchGeneration,
  paneToRerevealAfterClear,
  resolveActiveMatchIndex,
  shouldClearHighlights,
  type TextMatch,
} from './dualLogSearchSync.ts'
import { useAppStore } from '../../app/store.ts'
import { cs } from '../../i18n/cs.ts'
import { Button, IconButton } from '../../design-system/index.ts'
import {
  DEFAULT_SPLITTER_RATIO,
  MIN_PANE_PX,
  loadPreference,
  savePreference,
} from '../../persistence/preferencesRepository.ts'

import { logEditorTheme } from './codemirrorEditorTheme.ts'

const MAX_SEARCH_MATCHES = 5000
const SEARCH_DEBOUNCE_MS = 150

/** Plain-text search over a CodeMirror document. */
function findAllMatches(doc: Text, query: string, caseSensitive: boolean): TextMatch[] {
  if (!query) return []
  const normalize = caseSensitive ? undefined : (s: string) => s.toLowerCase()
  const cursor = new SearchCursor(doc, query, 0, doc.length, normalize)
  const results: TextMatch[] = []
  while (!cursor.next().done) {
    results.push({ from: cursor.value.from, to: cursor.value.to })
    if (results.length >= MAX_SEARCH_MATCHES) break
  }
  return results
}

function LogSearchBar(props: {
  query: string
  caseSensitive: boolean
  matches: TextMatch[]
  activeIndex: number
  inputRef?: RefObject<HTMLInputElement | null>
  testIdPrefix: string
  placeholder: string
  onQuery: (q: string) => void
  onCaseSensitive: (v: boolean) => void
  onPrev: () => void
  onNext: () => void
  onEscape: () => void
}) {
  return (
    <div className="log-search" data-testid={props.testIdPrefix}>
      <input
        ref={props.inputRef}
        type="text"
        className="log-search__input"
        placeholder={props.placeholder}
        aria-label={props.placeholder}
        value={props.query}
        onChange={(e) => props.onQuery(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault()
            if (e.shiftKey) props.onPrev()
            else props.onNext()
          } else if (e.key === 'Escape') {
            e.preventDefault()
            props.onEscape()
          }
        }}
        data-testid={`${props.testIdPrefix}-input`}
      />
      <IconButton
        label={cs.search.caseSensitiveLabel}
        aria-pressed={props.caseSensitive}
        onClick={() => props.onCaseSensitive(!props.caseSensitive)}
        data-testid={`${props.testIdPrefix}-case-toggle`}
      >
        Aa
      </IconButton>
      <Button
        variant="ghost"
        disabled={props.matches.length === 0}
        onClick={props.onPrev}
        aria-label={cs.search.prevMatch}
        data-testid={`${props.testIdPrefix}-prev`}
      >
        {cs.search.prevShort}
      </Button>
      <Button
        variant="ghost"
        disabled={props.matches.length === 0}
        onClick={props.onNext}
        aria-label={cs.search.nextMatch}
        data-testid={`${props.testIdPrefix}-next`}
      >
        {cs.search.nextShort}
      </Button>
      <span className="log-search__counter" data-testid={`${props.testIdPrefix}-counter`}>
        {props.matches.length === 0
          ? '—'
          : `${props.activeIndex + 1}/${props.matches.length}${props.matches.length >= MAX_SEARCH_MATCHES ? '+' : ''}`}
      </span>
    </div>
  )
}

export interface DualLogViewProps {
  /** Explicit mixed-set source — search persistence and stale guards use this id. */
  readonly correlationSourceId?: string
  readonly initialSearch?: {
    readonly originalQuery?: string
    readonly originalCase?: boolean
    readonly anonQuery?: string
    readonly anonCase?: boolean
  }
  readonly onSearchStateChange?: (state: {
    originalQuery: string
    originalCase: boolean
    anonQuery: string
    anonCase: boolean
  }) => void
}

export function DualLogView({
  correlationSourceId,
  initialSearch,
  onSearchStateChange,
}: DualLogViewProps = {}) {
  const leftHost = useRef<HTMLDivElement>(null)
  const rightHost = useRef<HTMLDivElement>(null)
  const rootRef = useRef<HTMLDivElement>(null)
  const leftView = useRef<EditorView | null>(null)
  const rightView = useRef<EditorView | null>(null)
  const syncRef = useRef<SyncControllers | null>(null)
  const wrapCompartment = useRef(new Compartment())
  const wrapRef = useRef(false)
  const wrapEnabled = useAppStore((s) => s.wrapEnabled)
  const splitterRatio = useAppStore((s) => s.splitterRatio)
  const sessionEpoch = useAppStore((s) => s.sessionEpoch)

  const originalSearchInputRef = useRef<HTMLInputElement>(null)
  const anonSearchInputRef = useRef<HTMLInputElement>(null)
  const originalSearchGen = useRef(createSearchGeneration())
  const anonSearchGen = useRef(createSearchGeneration())
  const syncRevealRaf = useRef(0)
  const originalMatchesRef = useRef<TextMatch[]>([])
  const anonMatchesRef = useRef<TextMatch[]>([])
  const originalActiveRef = useRef(-1)
  const anonActiveRef = useRef(-1)

  const [originalQuery, setOriginalQuery] = useState(initialSearch?.originalQuery ?? '')
  const [originalCase, setOriginalCase] = useState(initialSearch?.originalCase ?? false)
  const [originalMatches, setOriginalMatches] = useState<TextMatch[]>([])
  const [originalActive, setOriginalActive] = useState(-1)

  const [anonQuery, setAnonQuery] = useState(initialSearch?.anonQuery ?? '')
  const [anonCase, setAnonCase] = useState(initialSearch?.anonCase ?? false)
  const [anonMatches, setAnonMatches] = useState<TextMatch[]>([])
  const [anonActive, setAnonActive] = useState(-1)

  originalMatchesRef.current = originalMatches
  anonMatchesRef.current = anonMatches
  originalActiveRef.current = originalActive
  anonActiveRef.current = anonActive

  /** Select + scroll + cross-pane highlight for an original-document range. */
  function selectAndReveal(from: number, to: number, line: number, focus: 'left' | 'right' = 'left'): void {
    const left = leftView.current
    const right = rightView.current
    if (!left || !right) return
    const range = to > from ? EditorSelection.range(from, to) : EditorSelection.cursor(from)
    left.dispatch({
      selection: EditorSelection.create([range]),
      effects: [
        setHighlightEffect.of({ line, from, to: to > from ? to : undefined }),
        EditorView.scrollIntoView(range, { y: 'center', x: 'nearest', yMargin: 48 }),
      ],
    })
    right.dispatch({
      effects: [
        setHighlightEffect.of({ line, from, to: to > from ? to : undefined }),
        EditorView.scrollIntoView(from, { y: 'center', x: 'nearest', yMargin: 48 }),
      ],
    })
    if (focus === 'left') left.focus()
    else right.focus()
    if (syncRevealRaf.current) cancelAnimationFrame(syncRevealRaf.current)
    syncRevealRaf.current = requestAnimationFrame(() => {
      syncRevealRaf.current = 0
      if (!leftView.current || !rightView.current || !syncRef.current) return
      syncRef.current.syncNow('left')
    })
    useAppStore.getState().setFocusedLine(line)
  }

  function goToMatch(
    matches: TextMatch[],
    index: number,
    setActive: (n: number) => void,
    focus: 'left' | 'right',
  ): void {
    if (matches.length === 0) return
    const wrapped = ((index % matches.length) + matches.length) % matches.length
    const match = matches[wrapped]
    if (!match) return
    setActive(wrapped)
    const line = leftView.current?.state.doc.lineAt(match.from).number ?? 1
    selectAndReveal(match.from, match.to, line, focus)
  }

  function revealMatch(matches: readonly TextMatch[], index: number, focus: 'left' | 'right'): void {
    const match = matches[index]
    if (!match) return
    const line = leftView.current?.state.doc.lineAt(match.from).number ?? 1
    selectAndReveal(match.from, match.to, line, focus)
  }

  // 1) Original-pane search results — independent of anonQuery.
  useEffect(() => {
    const token = originalSearchGen.current.next()
    const timer = window.setTimeout(() => {
      if (!originalSearchGen.current.isCurrent(token)) return
      const left = leftView.current
      if (!left) return
      const previousMatches = originalMatchesRef.current
      const previousActive = originalActiveRef.current
      const matches = findAllMatches(left.state.doc, originalQuery, originalCase)
      const active = resolveActiveMatchIndex(matches, previousActive, previousMatches)
      setOriginalMatches(matches)
      setOriginalActive(active)
      if (active >= 0) {
        revealMatch(matches, active, 'left')
      }
    }, SEARCH_DEBOUNCE_MS)
    return () => window.clearTimeout(timer)
  }, [originalQuery, originalCase, sessionEpoch])

  // 2) Anonymized-pane search results — independent of originalQuery.
  useEffect(() => {
    const token = anonSearchGen.current.next()
    const timer = window.setTimeout(() => {
      if (!anonSearchGen.current.isCurrent(token)) return
      const session = getSessionModel()
      const left = leftView.current
      if (!session || !left || !anonQuery) {
        setAnonMatches([])
        setAnonActive(-1)
        return
      }
      const previousMatches = anonMatchesRef.current
      const previousActive = anonActiveRef.current
      const matches = findAnonymizedMatches(
        session.original,
        session.packed,
        session.plan,
        anonQuery,
        anonCase,
        MAX_SEARCH_MATCHES,
      )
      const active = resolveActiveMatchIndex(matches, previousActive, previousMatches)
      setAnonMatches(matches)
      setAnonActive(active)
      if (active >= 0) {
        revealMatch(matches, active, 'right')
      }
    }, SEARCH_DEBOUNCE_MS)
    return () => window.clearTimeout(timer)
  }, [anonQuery, anonCase, sessionEpoch])

  // 3) Shared highlight clear + re-reveal when one pane is emptied.
  useEffect(() => {
    if (shouldClearHighlights(originalQuery, anonQuery)) {
      if (leftView.current) clearHighlight(leftView.current)
      if (rightView.current) clearHighlight(rightView.current)
      return
    }

    if (!originalQuery && anonQuery) {
      const pane = paneToRerevealAfterClear({
        clearedPane: 'original',
        originalQuery,
        anonQuery,
        originalActive: originalActiveRef.current,
        anonActive: anonActiveRef.current,
      })
      if (pane === 'anonymized' && anonActiveRef.current >= 0) {
        revealMatch(anonMatchesRef.current, anonActiveRef.current, 'right')
      }
    } else if (originalQuery && !anonQuery) {
      const pane = paneToRerevealAfterClear({
        clearedPane: 'anonymized',
        originalQuery,
        anonQuery,
        originalActive: originalActiveRef.current,
        anonActive: anonActiveRef.current,
      })
      if (pane === 'original' && originalActiveRef.current >= 0) {
        revealMatch(originalMatchesRef.current, originalActiveRef.current, 'left')
      }
    }
  }, [originalQuery, anonQuery])

  // Cancel pending cross-pane sync reveal on unmount.
  useEffect(() => {
    const rafSlot = syncRevealRaf
    return () => {
      const id = rafSlot.current
      if (id) cancelAnimationFrame(id)
      rafSlot.current = 0
    }
  }, [])

  // Clear search only when the underlying document generation changes — not on every
  // planRevision bump from Inspector toggles (which also bump sessionEpoch).
  const docGeneration = sessionEpoch >= 0 ? (getSessionModel()?.meta.generation ?? null) : null
  const lastDocGeneration = useRef<string | null>(null)
  useEffect(() => {
    if (lastDocGeneration.current === null) {
      lastDocGeneration.current = docGeneration
      return
    }
    if (docGeneration === lastDocGeneration.current) return
    lastDocGeneration.current = docGeneration
    // Correlation remounts DualLogView per source; keep restored search when sourceId set.
    if (correlationSourceId) return
    originalSearchGen.current.invalidate()
    anonSearchGen.current.invalidate()
    setOriginalQuery('')
    setAnonQuery('')
    setOriginalMatches([])
    setAnonMatches([])
    setOriginalActive(-1)
    setAnonActive(-1)
    if (leftView.current) clearHighlight(leftView.current)
    if (rightView.current) clearHighlight(rightView.current)
  }, [docGeneration, correlationSourceId])

  useEffect(() => {
    onSearchStateChange?.({
      originalQuery,
      originalCase,
      anonQuery,
      anonCase,
    })
  }, [originalQuery, originalCase, anonQuery, anonCase, onSearchStateChange])

  useEffect(() => {
    wrapRef.current = wrapEnabled
    for (const view of [leftView.current, rightView.current]) {
      if (!view) continue
      const top = topVisibleLine(view)
      view.dispatch({
        effects: wrapCompartment.current.reconfigure(
          wrapEnabled ? EditorView.lineWrapping : [],
        ),
      })
      if (top > 0) scrollToPhysicalLine(view, top, 0)
    }
    syncRef.current?.syncNow('left')
  }, [wrapEnabled])

  useEffect(() => {
    const session = getSessionModel()
    if (!session || !leftHost.current || !rightHost.current) return

    const initialWrap = useAppStore.getState().wrapEnabled
    wrapRef.current = initialWrap

    const allowSelectionCopy = session.meta.mode !== 'large'
    const getIndex = () => getSessionModel()?.packed ?? null
    const getPlan = () => getSessionModel()?.plan ?? null
    const getOriginal = () => getSessionModel()?.original ?? ''

    const baseExt = [
      lineNumbers(),
      drawSelection(),
      highlightActiveLine(),
      highlightActiveLineGutter(),
      highlightField,
      EditorView.editable.of(false),
      keymap.of(defaultKeymap),
      wrapCompartment.current.of(initialWrap ? EditorView.lineWrapping : []),
      logEditorTheme,
    ]

    const syncHighlightFrom = (view: EditorView) => {
      const sel = view.state.selection.main
      const line = view.state.doc.lineAt(sel.head)
      const other = view === leftView.current ? rightView.current : leftView.current
      const packed = getIndex()
      const plan = getPlan()
      let matchFrom: number | undefined
      let matchTo: number | undefined
      if (packed && plan) {
        for (let i = 0; i < packed.starts.length; i++) {
          if (packed.lines[i] !== line.number) continue
          const start = packed.starts[i]!
          const end = start + packed.lengths[i]!
          if (sel.head >= start && sel.head <= end) {
            matchFrom = start
            matchTo = end
            break
          }
          if (matchFrom == null || Math.abs(start - sel.head) < Math.abs(matchFrom - sel.head)) {
            matchFrom = start
            matchTo = end
          }
        }
      }
      dispatchHighlight(view, line.number, matchFrom, matchTo)
      if (other) {
        dispatchHighlight(other, line.number, matchFrom, matchTo)
      }
      useAppStore.getState().setFocusedLine(line.number)
    }

    const selectWordAtClick = (view: EditorView) => {
      const sel = view.state.selection.main
      if (!sel.empty) return
      const word = view.state.wordAt(sel.head)
      if (word) {
        view.dispatch({ selection: EditorSelection.create([word]) })
      }
    }

    const left = new EditorView({
      state: EditorState.create({
        doc: session.doc,
        extensions: [
          ...baseExt,
          createOriginalMatchHighlightPlugin(getIndex, getPlan),
          highlightSelectionMatches(),
          EditorView.updateListener.of((update) => {
            if (update.selectionSet) syncHighlightFrom(update.view)
          }),
          EditorView.domEventHandlers({
            click: () => {
              queueMicrotask(() => selectWordAtClick(left))
              return false
            },
          }),
          EditorView.contentAttributes.of({
            'aria-label': 'Originální log',
            'data-pane': 'original',
            tabindex: '0',
          }),
        ],
      }),
      parent: leftHost.current,
    })

    const right = new EditorView({
      state: EditorState.create({
        doc: session.doc,
        extensions: [
          ...baseExt,
          createAnonymizedViewportPlugin(getIndex, getPlan),
          ...createAnonymizedSecurityExtensions({
            getOriginal,
            getIndex,
            getPlan,
            allowSelectionCopy,
          }),
          EditorView.updateListener.of((update) => {
            if (update.selectionSet) syncHighlightFrom(update.view)
          }),
          EditorView.domEventHandlers({
            keydown(event) {
              if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'f') {
                event.preventDefault()
                anonSearchInputRef.current?.focus()
                anonSearchInputRef.current?.select()
                return true
              }
              return false
            },
            click: () => {
              queueMicrotask(() => selectWordAtClick(right))
              return false
            },
          }),
          keymap.of(
            searchKeymap.map((binding) => ({
              ...binding,
              run: () => true,
            })),
          ),
          EditorView.contentAttributes.of({
            'aria-label': 'Anonymizovaný log',
            'data-pane': 'anonymized',
            tabindex: '0',
          }),
        ],
      }),
      parent: rightHost.current,
    })

    leftView.current = left
    rightView.current = right

    const sync = attachSynchronizedEditors(left, right, {
      getWrap: () => wrapRef.current,
      getPacked: getIndex,
      getPlan: getPlan,
      leftIsOriginal: true,
    })
    syncRef.current = sync

    const jumpToMatchIndex = (matchIndex: number): number => {
      const packed = getIndex()
      if (!packed || matchIndex < 0 || matchIndex >= packed.starts.length) return -1
      const start = packed.starts[matchIndex]!
      const end = start + packed.lengths[matchIndex]!
      const line = packed.lines[matchIndex]!
      const docLen = left.state.doc.length
      const from = Math.max(0, Math.min(start, docLen))
      const to = Math.max(from, Math.min(end, docLen))
      selectAndReveal(from, to, line, 'left')
      useAppStore.getState().setOccurrenceIndex(matchIndex)
      return line
    }

    registerDualLogBridge({
      left,
      right,
      sync,
      setWrap: (wrap) => {
        useAppStore.getState().setWrapEnabled(wrap)
      },
      getWrap: () => wrapRef.current,
      jumpToMatchIndex,
      highlightLine: (line) => {
        dispatchHighlight(left, line)
        dispatchHighlight(right, line)
        scrollToPhysicalLine(left, line, 0)
        scrollToPhysicalLine(right, line, 0)
      },
      refreshDecorations: () => {
        left.dispatch({ effects: refreshAnonEffect.of(null) })
        right.dispatch({ effects: refreshAnonEffect.of(null) })
        sync.syncNow('left')
      },
      getTopLine: () => topVisibleLine(left),
      focusSearch: () => {
        originalSearchInputRef.current?.focus()
        originalSearchInputRef.current?.select()
      },
      destroy: () => {
        sync.destroy()
        left.destroy()
        right.destroy()
      },
    })

    const ratio = loadPreference('splitterRatio', DEFAULT_SPLITTER_RATIO)
    applySplitterRatio(rootRef.current, ratio)

    return () => {
      registerDualLogBridge(null)
      sync.destroy()
      left.destroy()
      right.destroy()
      leftView.current = null
      rightView.current = null
      syncRef.current = null
    }
  }, [])

  return (
    <div className="dual-log surface-data" data-testid="dual-log" ref={rootRef}>
      <section className="dual-log__pane dual-log__pane--left" aria-labelledby="pane-original-title">
        <header className="dual-log__pane-header">
          <div className="dual-log__pane-title">
            <h2 id="pane-original-title">{cs.workspace.paneOriginal}</h2>
          </div>
          <LogSearchBar
            query={originalQuery}
            caseSensitive={originalCase}
            matches={originalMatches}
            activeIndex={originalActive}
            inputRef={originalSearchInputRef}
            testIdPrefix="log-search"
            placeholder={cs.search.placeholder}
            onQuery={setOriginalQuery}
            onCaseSensitive={setOriginalCase}
            onPrev={() => goToMatch(originalMatches, originalActive - 1, setOriginalActive, 'left')}
            onNext={() => goToMatch(originalMatches, originalActive + 1, setOriginalActive, 'left')}
            onEscape={() => {
              setOriginalQuery('')
              leftView.current?.focus()
            }}
          />
        </header>
        <div ref={leftHost} className="dual-log__editor" data-testid="pane-original" />
      </section>
      <div
        className="dual-log__splitter"
        role="separator"
        aria-orientation="vertical"
        aria-label="Šířka panelů"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(splitterRatio * 100)}
        tabIndex={0}
        data-testid="pane-splitter"
        onPointerDown={(event) => {
          event.preventDefault()
          const root = rootRef.current
          if (!root) return
          const startX = event.clientX
          const startRatio = getCurrentRatio(root)
          const onMove = (ev: PointerEvent) => {
            const rect = root.getBoundingClientRect()
            const dx = ev.clientX - startX
            const next = startRatio + dx / rect.width
            applySplitterRatio(root, next)
          }
          const onUp = () => {
            window.removeEventListener('pointermove', onMove)
            window.removeEventListener('pointerup', onUp)
            const r = getCurrentRatio(root)
            savePreference('splitterRatio', r)
            useAppStore.getState().setSplitterRatio(r)
            syncRef.current?.syncNow('left')
          }
          window.addEventListener('pointermove', onMove)
          window.addEventListener('pointerup', onUp)
        }}
        onKeyDown={(event) => {
          const root = rootRef.current
          if (!root) return
          let ratio = getCurrentRatio(root)
          if (event.key === 'ArrowLeft') ratio -= 0.02
          else if (event.key === 'ArrowRight') ratio += 0.02
          else return
          event.preventDefault()
          applySplitterRatio(root, ratio)
          savePreference('splitterRatio', getCurrentRatio(root))
          syncRef.current?.syncNow('left')
        }}
      />
      <section className="dual-log__pane dual-log__pane--right" aria-labelledby="pane-anon-title">
        <header className="dual-log__pane-header">
          <div className="dual-log__pane-title">
            <h2 id="pane-anon-title">{cs.workspace.paneAnonymized}</h2>
          </div>
          <LogSearchBar
            query={anonQuery}
            caseSensitive={anonCase}
            matches={anonMatches}
            activeIndex={anonActive}
            inputRef={anonSearchInputRef}
            testIdPrefix="log-search-anon"
            placeholder={cs.search.placeholderAnon}
            onQuery={setAnonQuery}
            onCaseSensitive={setAnonCase}
            onPrev={() => goToMatch(anonMatches, anonActive - 1, setAnonActive, 'right')}
            onNext={() => goToMatch(anonMatches, anonActive + 1, setAnonActive, 'right')}
            onEscape={() => {
              setAnonQuery('')
              rightView.current?.focus()
            }}
          />
          <LargeLogCopyBanner />
        </header>
        <div ref={rightHost} className="dual-log__editor" data-testid="pane-anonymized" />
      </section>
    </div>
  )
}

function LargeLogCopyBanner() {
  const sessionEpoch = useAppStore((s) => s.sessionEpoch)
  const session = sessionEpoch >= 0 ? getSessionModel() : null
  if (!session || session.meta.mode !== 'large') return null
  return (
    <p className="dual-log__copy-blocked" role="status" data-testid="large-log-copy-blocked">
      {cs.workspace.largeLogCopyBlocked}
    </p>
  )
}

function clampRatio(ratio: number, rootWidth: number): number {
  const min = MIN_PANE_PX / rootWidth
  const max = 1 - min
  if (max <= min) return 0.5
  return Math.max(min, Math.min(max, ratio))
}

function applySplitterRatio(root: HTMLElement | null, ratio: number): void {
  if (!root) return
  const width = root.getBoundingClientRect().width || 1
  const r = clampRatio(ratio, width)
  root.style.setProperty('--split-left', `${r * 100}%`)
}

function getCurrentRatio(root: HTMLElement): number {
  const raw = getComputedStyle(root).getPropertyValue('--split-left').trim()
  if (raw.endsWith('%')) return Number.parseFloat(raw) / 100
  return DEFAULT_SPLITTER_RATIO
}
