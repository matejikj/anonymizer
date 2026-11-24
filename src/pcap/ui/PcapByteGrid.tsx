import { useMemo, useCallback, useEffect, useRef, useState, type KeyboardEvent, type MouseEvent } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import type { ByteSource, DissectionNode } from '../dissection/types'
import { findDeepestNodeAtOffset, nodePath } from '../dissection/types'
import { highlightRangeForPane } from './fieldCounterpartMapping.ts'
import { getPcapSession } from './pcapSession.ts'
import type { PcapDataView } from './pcapUiPrefs.ts'
import { usePcapPanelScrollSync } from './pcapPanelScrollSync.tsx'

const BYTES_PER_ROW = 16
const MID_GAP_AFTER = 8
// PF-13: byte rows are virtualized like PcapPacketTables' packet list. Row height is measured
// from an actually-rendered row (not hardcoded) so the spacer/translate math always matches the
// real CSS box — this constant is only the pre-measurement fallback used for the very first
// paint and in environments without real layout (unit tests).
const BYTE_ROW_HEIGHT_FALLBACK = 20
const OVERSCAN_ROWS = 10

function useViewportHeight(ref: { current: HTMLDivElement | null }, enabled: boolean): number {
  const [height, setHeight] = useState(0)
  useEffect(() => {
    if (!enabled) return
    const el = ref.current
    if (!el) return
    if (typeof ResizeObserver === 'undefined') {
      setHeight(el.clientHeight)
      return
    }
    const ro = new ResizeObserver((entries) => {
      const entry = entries[0]
      if (entry) setHeight(entry.contentRect.height)
    })
    ro.observe(el)
    setHeight(el.clientHeight)
    return () => ro.disconnect()
  }, [ref, enabled])
  return height
}

export interface PcapByteGridProps {
  readonly sources: readonly ByteSource[]
  readonly roots: readonly DissectionNode[]
  readonly loading?: boolean
  readonly dataView?: PcapDataView
}

export function PcapByteGrid({ sources, roots, loading = false, dataView: dataViewProp }: PcapByteGridProps) {
  const activeByteSourceId = usePcapStore((s) => s.activeByteSourceId)
  const setActiveByteSourceId = usePcapStore((s) => s.setActiveByteSourceId)
  const selectedByteOffset = usePcapStore((s) => s.selectedByteOffset)
  const selectedFieldPath = usePcapStore((s) => s.selectedFieldPath)
  const setSelectedByteOffset = usePcapStore((s) => s.setSelectedByteOffset)
  const setSelectedFieldPath = usePcapStore((s) => s.setSelectedFieldPath)
  const selectedPacketIndex = usePcapStore((s) => s.selectedPacketIndex)
  const pushSelectionSnapshot = usePcapStore((s) => s.pushSelectionSnapshot)
  const storeDataView = usePcapStore((s) => s.dataView)
  const dataView = dataViewProp ?? storeDataView
  const gridRef = useRef<HTMLDivElement>(null)
  const [copyFlash, setCopyFlash] = useState(false)
  const [scrollTop, setScrollTop] = useState(0)
  const [rowHeight, setRowHeight] = useState(BYTE_ROW_HEIGHT_FALLBACK)
  // Loading replaces the scroll element; measure and observe its replacement as well.
  const viewportHeight = useViewportHeight(gridRef, !loading)

  const source = sources.find((s) => s.id === activeByteSourceId) ?? sources[0]
  const bytes = source?.bytes ?? new Uint8Array(0)
  const fieldMap = source?.fieldMap ?? []
  const planPkt = getPcapSession()?.plan.packets[selectedPacketIndex]

  const onGridScroll = usePcapPanelScrollSync({
    channel: `bytes:${source?.id ?? 'frame'}`, dataView, viewport: gridRef,
    enabled: !loading, onLocalScroll: setScrollTop,
  })

  const measureFirstRow = useCallback((el: HTMLDivElement | null) => {
    if (!el) return
    const h = el.getBoundingClientRect().height
    if (h > 0) setRowHeight((prev) => (Math.abs(prev - h) > 0.5 ? h : prev))
  }, [])

  const highlightResult = useMemo(
    () =>
      highlightRangeForPane({
        fieldPath: selectedFieldPath,
        byteOffset: selectedByteOffset,
        roots,
        planPkt,
      }),
    [selectedFieldPath, selectedByteOffset, roots, planPkt],
  )
  const highlightRange = highlightResult === 'unmapped' ? null : highlightResult
  const unmapped = highlightResult === 'unmapped'

  const rows = useMemo(() => {
    const out: { offset: number; hex: number[]; ascii: string }[] = []
    for (let off = 0; off < bytes.length; off += BYTES_PER_ROW) {
      const slice = bytes.slice(off, off + BYTES_PER_ROW)
      const hex = Array.from(slice)
      const ascii = hex
        .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
        .join('')
      out.push({ offset: off, hex, ascii })
    }
    return out
  }, [bytes])

  // PF-13: precompute offset -> changeKind once instead of scanning the whole fieldMap for
  // every byte (changeKindAt was O(bytes x fields)). First fieldMap entry covering an offset
  // with a real changeKind still wins, matching the original linear-scan-first-match order.
  const changeKindByOffset = useMemo(() => {
    const arr: string[] = Array.from({ length: bytes.length }, () => 'none')
    for (const n of fieldMap) {
      if (!n.changeKind || n.changeKind === 'none') continue
      const start = Math.max(0, n.offset)
      const end = Math.min(bytes.length, n.offset + n.length)
      for (let i = start; i < end; i++) {
        if (arr[i] === 'none') arr[i] = n.changeKind
      }
    }
    return arr
  }, [fieldMap, bytes.length])

  const { start: rowStart, end: rowEnd } = useMemo(() => {
    if (rows.length === 0) return { start: 0, end: 0 }
    const first = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN_ROWS)
    const visibleCount = Math.ceil(viewportHeight / rowHeight) + OVERSCAN_ROWS * 2
    const last = Math.min(rows.length, first + Math.max(visibleCount, 1))
    return { start: first, end: last }
  }, [rows.length, scrollTop, rowHeight, viewportHeight])

  const selectOffset = useCallback(
    (offset: number) => {
      setSelectedByteOffset(offset)
      const map = fieldMap.length > 0 ? fieldMap : flattenFromRoots(roots)
      const node = findDeepestNodeAtOffset(map, offset)
      const path = node ? nodePath(node, roots) : null
      setSelectedFieldPath(path)
      pushSelectionSnapshot({
        packetIndex: selectedPacketIndex,
        fieldPath: path,
        byteOffset: offset,
      })
    },
    [fieldMap, roots, selectedPacketIndex, setSelectedByteOffset, setSelectedFieldPath, pushSelectionSnapshot],
  )

  // PF-13: with virtualization the target byte's row may not be mounted yet, so bring it into
  // the scroll window first (mirrors PcapPacketTables' selection-driven scroll adjustment)...
  useEffect(() => {
    if (selectedByteOffset === null) return
    const el = gridRef.current
    if (!el) return
    const rowIndex = Math.floor(selectedByteOffset / BYTES_PER_ROW)
    const rowTop = rowIndex * rowHeight
    const rowBottom = rowTop + rowHeight
    let next = el.scrollTop
    if (rowTop < el.scrollTop) next = rowTop
    else if (rowBottom > el.scrollTop + el.clientHeight) next = rowBottom - el.clientHeight
    if (Math.abs(next - el.scrollTop) > 0.5) {
      el.scrollTop = next
      setScrollTop(next)
    }
  }, [selectedByteOffset, rowHeight])

  // ...then, once that row is actually rendered, scrollIntoView for exact (incl. horizontal)
  // alignment. Do NOT depend on rowStart/rowEnd — scrollIntoView can change scrollTop and
  // would re-fire this effect forever (Maximum update depth exceeded).
  useEffect(() => {
    if (selectedByteOffset === null) return
    const el = gridRef.current?.querySelector(`[data-byte-offset="${selectedByteOffset}"]`)
    el?.scrollIntoView({ block: 'nearest', inline: 'nearest' })
  }, [selectedByteOffset])

  const flashCopied = () => {
    setCopyFlash(true)
    window.setTimeout(() => setCopyFlash(false), 1200)
  }

  const onCopy = async () => {
    const slice = highlightRange
      ? bytes.slice(highlightRange.start, highlightRange.end)
      : bytes
    if (slice.length === 0) return
    const hex = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ')
    try {
      await navigator.clipboard.writeText(hex)
      flashCopied()
    } catch {
      // ignore
    }
  }

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (selectedByteOffset === null && bytes.length > 0) {
      if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
        event.preventDefault()
        selectOffset(0)
      }
      return
    }
    if (selectedByteOffset === null) return
    if (event.key === 'ArrowRight') {
      event.preventDefault()
      selectOffset(Math.min(bytes.length - 1, selectedByteOffset + 1))
    } else if (event.key === 'ArrowLeft') {
      event.preventDefault()
      selectOffset(Math.max(0, selectedByteOffset - 1))
    } else if (event.key === 'ArrowDown') {
      event.preventDefault()
      selectOffset(Math.min(bytes.length - 1, selectedByteOffset + BYTES_PER_ROW))
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      selectOffset(Math.max(0, selectedByteOffset - BYTES_PER_ROW))
    }
  }

  if (loading) {
    return (
      <div className="pcap-byte-grid-wrap pcap-byte-grid-wrap--loading" data-testid="pcap-byte-grid">
        <p className="pcap-byte-grid__loading">{cs.pcap.detail.loading}</p>
      </div>
    )
  }

  const selectionLen = highlightRange ? highlightRange.end - highlightRange.start : 0
  const copyLabel = copyFlash
    ? cs.pcap.detail.copied
    : highlightRange
      ? cs.pcap.detail.copySelection
      : cs.pcap.detail.copyAll

  return (
    <div className="pcap-byte-grid-wrap" data-testid="pcap-byte-grid" data-data-view={dataView}>
      {unmapped ? (
        <p className="pcap-byte-grid__unmapped" role="status" data-testid="pcap-byte-unmapped">
          {cs.pcap.detail.noDirectCounterpart}
        </p>
      ) : null}

      {sources.length > 1 ? (
        <div className="pcap-byte-grid__tabs" role="tablist" aria-label={cs.pcap.detail.hexSources}>
          {sources.map((s) => (
            <button
              key={s.id}
              type="button"
              role="tab"
              aria-selected={s.id === source?.id}
              className={s.id === source?.id ? 'is-active' : undefined}
              onClick={() => setActiveByteSourceId(s.id)}
            >
              {s.label}
            </button>
          ))}
        </div>
      ) : null}

      <div className="pcap-byte-grid__chrome">
        <div className="pcap-byte-grid__meta" data-testid="pcap-byte-meta">
          <span className="pcap-byte-grid__meta-len">
            {cs.pcap.detail.bytesMeta.replace('{n}', String(bytes.length))}
          </span>
          {highlightRange ? (
            <span className="pcap-byte-grid__meta-sel" data-testid="pcap-byte-selection">
              {cs.pcap.detail.patchMeta
                .replace('{off}', String(highlightRange.start))
                .replace('{len}', String(selectionLen))}
            </span>
          ) : selectedByteOffset !== null ? (
            <span className="pcap-byte-grid__meta-sel">
              {cs.pcap.detail.byteOffset.replace('{off}', String(selectedByteOffset))}
            </span>
          ) : (
            <span className="pcap-byte-grid__meta-hint">{cs.pcap.detail.hexSelectHint}</span>
          )}
        </div>
        <button
          type="button"
          className={`pcap-byte-grid__copy${copyFlash ? ' is-copied' : ''}`}
          data-testid="pcap-byte-copy"
          onClick={() => void onCopy()}
          disabled={bytes.length === 0}
        >
          {copyLabel}
        </button>
      </div>

      <div
        ref={gridRef}
        className="pcap-byte-grid"
        tabIndex={0}
        role="grid"
        aria-label={cs.pcap.detail.hex}
        onKeyDown={onKeyDown}
        onScroll={onGridScroll}
      >
        {bytes.length === 0 ? (
          <p className="pcap-byte-grid__empty">{cs.pcap.detail.hexEmpty}</p>
        ) : (
          <div style={{ height: rows.length * rowHeight, position: 'relative' }}>
            <div style={{ transform: `translateY(${rowStart * rowHeight}px)` }}>
              {rows.slice(rowStart, rowEnd).map((row, i) => (
                <div
                  key={row.offset}
                  ref={i === 0 ? measureFirstRow : undefined}
                  className="pcap-byte-grid__row"
                  role="row"
                >
                  <span className="pcap-byte-grid__offset" role="rowheader">
                    {row.offset.toString(16).padStart(8, '0')}
                  </span>
                  <span className="pcap-byte-grid__hex" role="gridcell">
                    {row.hex.map((b, j) => {
                      const abs = row.offset + j
                      const inRange =
                        highlightRange && abs >= highlightRange.start && abs < highlightRange.end
                      const isCaret = selectedByteOffset === abs
                      const changeKind = changeKindByOffset[abs] ?? 'none'
                      return (
                        <span key={abs} className="pcap-byte-grid__hex-cell">
                          {j === MID_GAP_AFTER ? <span className="pcap-byte-grid__gap" aria-hidden /> : null}
                          <ByteCell
                            byte={b}
                            abs={abs}
                            highlighted={!!inRange}
                            caret={isCaret}
                            changeKind={changeKind}
                            onSelect={selectOffset}
                          />
                        </span>
                      )
                    })}
                  </span>
                  <span className="pcap-byte-grid__ascii" role="gridcell">
                    {row.ascii.split('').map((ch, j) => {
                      const abs = row.offset + j
                      const inRange =
                        highlightRange && abs >= highlightRange.start && abs < highlightRange.end
                      const isCaret = selectedByteOffset === abs
                      return (
                        <span key={abs} className="pcap-byte-grid__ascii-cell">
                          {j === MID_GAP_AFTER ? <span className="pcap-byte-grid__gap pcap-byte-grid__gap--ascii" aria-hidden /> : null}
                          <span
                            className={`pcap-byte-grid__ascii-char${inRange ? ' is-highlighted' : ''}${isCaret ? ' is-caret' : ''}`}
                            data-byte-offset={abs}
                            onClick={() => selectOffset(abs)}
                          >
                            {ch}
                          </span>
                        </span>
                      )
                    })}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function ByteCell({
  byte,
  abs,
  highlighted,
  caret,
  changeKind,
  onSelect,
}: {
  byte: number
  abs: number
  highlighted: boolean
  caret: boolean
  changeKind: string
  onSelect: (offset: number) => void
}) {
  const changeClass = changeKind !== 'none' ? ` pcap-byte-grid__byte--${changeKind}` : ''
  return (
    <span
      className={`pcap-byte-grid__byte${highlighted ? ' is-highlighted' : ''}${caret ? ' is-caret' : ''}${changeClass}`}
      data-byte-offset={abs}
      onClick={(e: MouseEvent) => {
        e.stopPropagation()
        onSelect(abs)
      }}
    >
      {byte.toString(16).padStart(2, '0')}
    </span>
  )
}

function flattenFromRoots(roots: readonly DissectionNode[]): DissectionNode[] {
  const out: DissectionNode[] = []
  const walk = (list: readonly DissectionNode[]) => {
    for (const n of list) {
      if (n.length > 0) out.push(n)
      walk(n.children)
    }
  }
  walk(roots)
  return out
}

