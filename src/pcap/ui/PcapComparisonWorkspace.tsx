/**
 * Dual Original|Anonymized workspace with accessible compare splitter,
 * or single-pane mode under PCAP_DUAL_PANE_MIN_WIDTH.
 */

import { useCallback, useEffect, useRef } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { PcapDataPane } from './PcapDataPane.tsx'
import { PcapNarrowWorkspace } from './PcapNarrowWorkspace.tsx'
import {
  PCAP_COMPARE_RATIO_DEFAULT,
  PCAP_COMPARE_RATIO_MAX,
  PCAP_COMPARE_RATIO_MIN,
  PCAP_COMPARE_RATIO_STEP,
  clampCompareRatio,
  layoutFromWorkspaceWidth,
  nextCompareLayout,
} from './pcapCompareLayout.ts'
import { columnsForWorkspaceWidth } from './pcapUiPrefs.ts'
import { PcapPanelScrollSyncProvider } from './pcapPanelScrollSync.tsx'

export function PcapComparisonWorkspace() {
  return <PcapPanelScrollSyncProvider><ComparisonWorkspace /></PcapPanelScrollSyncProvider>
}

function ComparisonWorkspace() {
  const compareLayout = usePcapStore((s) => s.compareLayout)
  const setCompareLayout = usePcapStore((s) => s.setCompareLayout)
  const setWorkspaceWidth = usePcapStore((s) => s.setWorkspaceWidth)
  const focusedPane = usePcapStore((s) => s.focusedPane)
  const setFocusedPane = usePcapStore((s) => s.setFocusedPane)
  const compareRatio = usePcapStore((s) => s.compareRatio)
  const setCompareRatio = usePcapStore((s) => s.setCompareRatio)
  const layoutMode = usePcapStore((s) => s.layoutMode)
  const setColumns = usePcapStore((s) => s.setColumns)
  const setLiveAnnounce = usePcapStore((s) => s.setLiveAnnounce)
  const selectedPacketIndex = usePcapStore((s) => s.selectedPacketIndex)

  const rootRef = useRef<HTMLDivElement>(null)
  const ratioRef = useRef(compareRatio)
  const rafRef = useRef(0)
  ratioRef.current = compareRatio

  useEffect(() => {
    const el = rootRef.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      const width = entries[0]?.contentRect.width ?? el.clientWidth
      // Ignore zero-width measurements (hidden / not laid out) to avoid dual↔single oscillation.
      if (width < 1) return
      const state = usePcapStore.getState()
      if (Math.abs(state.workspaceWidth - width) >= 0.5) {
        setWorkspaceWidth(width)
      }
      const nextLayout = nextCompareLayout(width, state.compareLayout)
      if (state.compareLayout !== nextLayout) setCompareLayout(nextLayout)
      const compacted = columnsForWorkspaceWidth(usePcapStore.getState().columns, width)
      const cur = usePcapStore.getState().columns
      if (compacted.some((c, i) => c.visible !== cur[i]?.visible)) {
        setColumns(compacted)
      }
    })
    ro.observe(el)
    const initial = el.clientWidth
    if (initial >= 1) {
      const state = usePcapStore.getState()
      if (Math.abs(state.workspaceWidth - initial) >= 0.5) {
        setWorkspaceWidth(initial)
      }
      const initialLayout = layoutFromWorkspaceWidth(initial)
      if (state.compareLayout !== initialLayout) setCompareLayout(initialLayout)
    }
    return () => ro.disconnect()
  }, [setCompareLayout, setWorkspaceWidth, setColumns])

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key !== 'F6') return
      const target = event.target as HTMLElement | null
      if (
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.tagName === 'SELECT' ||
          target.isContentEditable)
      ) {
        return
      }
      event.preventDefault()
      const next = focusedPane === 'original' ? 'anonymized' : 'original'
      setFocusedPane(next)
      setLiveAnnounce(
        (next === 'original'
          ? cs.pcap.a11y.focusOriginal
          : cs.pcap.a11y.focusAnonymized
        ).replace('{n}', String(selectedPacketIndex >= 0 ? selectedPacketIndex + 1 : '—')),
      )
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [focusedPane, setFocusedPane, setLiveAnnounce, selectedPacketIndex])

  const applyLiveRatio = useCallback((next: number) => {
    const clamped = clampCompareRatio(next)
    ratioRef.current = clamped
    const root = rootRef.current
    if (!root) return
    cancelAnimationFrame(rafRef.current)
    rafRef.current = requestAnimationFrame(() => {
      root.style.setProperty('--pcap-compare-left', `${clamped}fr`)
      root.style.setProperty('--pcap-compare-right', `${1 - clamped}fr`)
    })
  }, [])

  const commitRatio = useCallback(() => {
    setCompareRatio(ratioRef.current, { persist: true })
  }, [setCompareRatio])

  const onSplitterPointerDown = useCallback(
    (event: React.PointerEvent<HTMLDivElement>) => {
      event.preventDefault()
      const root = rootRef.current
      if (!root) return
      const rect = root.getBoundingClientRect()
      const startX = event.clientX
      const startRatio = ratioRef.current
      const onMove = (ev: PointerEvent) => {
        applyLiveRatio(startRatio + (ev.clientX - startX) / rect.width)
      }
      const onUp = () => {
        window.removeEventListener('pointermove', onMove)
        window.removeEventListener('pointerup', onUp)
        commitRatio()
      }
      window.addEventListener('pointermove', onMove)
      window.addEventListener('pointerup', onUp)
    },
    [applyLiveRatio, commitRatio],
  )

  const onSplitterKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'ArrowLeft') {
      event.preventDefault()
      setCompareRatio(compareRatio - PCAP_COMPARE_RATIO_STEP)
    } else if (event.key === 'ArrowRight') {
      event.preventDefault()
      setCompareRatio(compareRatio + PCAP_COMPARE_RATIO_STEP)
    } else if (event.key === 'Home') {
      event.preventDefault()
      setCompareRatio(PCAP_COMPARE_RATIO_MIN)
    } else if (event.key === 'End') {
      event.preventDefault()
      setCompareRatio(PCAP_COMPARE_RATIO_MAX)
    }
  }

  if (layoutMode === 'narrow') {
    return (
      <div
        ref={rootRef}
        className="pcap-comparison-workspace pcap-comparison-workspace--narrow"
        data-testid="pcap-comparison-workspace"
        data-layout="single"
      >
        <PcapNarrowWorkspace />
      </div>
    )
  }

  if (compareLayout === 'single') {
    return (
      <div
        ref={rootRef}
        className="pcap-comparison-workspace pcap-comparison-workspace--single"
        data-testid="pcap-comparison-workspace"
        data-layout="single"
      >
        <PcapDataPane
          dataView={focusedPane}
          focused
          onFocusPane={() => setFocusedPane(focusedPane)}
        />
      </div>
    )
  }

  return (
    <div
      ref={rootRef}
      className="pcap-comparison-workspace pcap-comparison-workspace--dual"
      data-testid="pcap-comparison-workspace"
      data-layout="dual"
      style={
        {
          '--pcap-compare-left': `${compareRatio}fr`,
          '--pcap-compare-right': `${1 - compareRatio}fr`,
        } as React.CSSProperties
      }
    >
      <PcapDataPane
        dataView="original"
        focused={focusedPane === 'original'}
        onFocusPane={() => setFocusedPane('original')}
      />
      <div
        className="pcap-comparison-workspace__splitter"
        role="separator"
        aria-orientation="vertical"
        aria-label={cs.pcap.workspace.compareSplitterLabel}
        aria-valuemin={Math.round(PCAP_COMPARE_RATIO_MIN * 100)}
        aria-valuemax={Math.round(PCAP_COMPARE_RATIO_MAX * 100)}
        aria-valuenow={Math.round(compareRatio * 100)}
        tabIndex={0}
        data-testid="pcap-compare-splitter"
        onPointerDown={onSplitterPointerDown}
        onKeyDown={onSplitterKeyDown}
        onDoubleClick={() => setCompareRatio(PCAP_COMPARE_RATIO_DEFAULT)}
      />
      <PcapDataPane
        dataView="anonymized"
        focused={focusedPane === 'anonymized'}
        onFocusPane={() => setFocusedPane('anonymized')}
      />
    </div>
  )
}
