import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  memo,
  type KeyboardEvent,
  type MouseEvent,
  type PointerEvent,
  type DragEvent,
  type RefObject,
} from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { getPcapSession, getPacketRowMeta, getPacketEndpoints, getPacketProtocols } from './pcapSession.ts'
import { unifiedSpansForPacket } from '../coverage/buildUnifiedCoverage'
import type { PacketRecordDescriptor } from '../domain/types'
import { formatTimestamp } from './formatters.ts'
import {
  columnLabel,
  gridTemplateForColumns,
  visibleColumns,
  type PcapColumnId,
  type PcapColumnPref,
  type PcapDataView,
} from './pcapUiPrefs.ts'
import {
  deltaFromPrevious,
  highestProtocol,
  packetInfoWithPatches,
  packetMark,
  relativeTimeSeconds,
} from './packetListRowModel.ts'
import { NO_COLOR_SLOT } from '../coloring/types'
import { compileColoringRules } from '../coloring/compileColoringRules'
import { applyColorPaletteToElement } from './usePcapPacketColoring.ts'
import { conversationIdFromFilterContext } from '../coloring/conversation'
import { buildFilterContextFromSession } from './pcapSession.ts'
import {
  registerPcapListScrollPane,
  onPcapListUserScroll,
  isPcapListScrollEcho,
  PCAP_LIST_ROW_HEIGHT,
  virtualWindowStart,
} from './pcapScrollSync.ts'
import { buildCreateColoringRuleOptions } from './createColoringRuleFrom.ts'
import type { PcapColoringRule } from '../coloring/types'

const ROW_HEIGHT = 28
const OVERSCAN = 8

function useVirtualWindow(scrollTop: number, viewportHeight: number, count: number) {
  return useMemo(() => {
    const start = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN)
    const visible = Math.ceil(viewportHeight / ROW_HEIGHT) + OVERSCAN * 2
    const end = Math.min(count, start + visible)
    return { start, end }
  }, [scrollTop, viewportHeight, count])
}

export interface PcapPacketTablesProps {
  readonly dataView?: PcapDataView
  readonly filteredIndices?: readonly number[]
  readonly scrollTop?: number
  readonly onScrollTop?: (top: number) => void
  readonly testId?: string
}

interface PacketRowProps {
  packetIndex: number
  selected: boolean
  marked: boolean
  onSelect: (index: number) => void
  onContextMenu: (index: number, event: MouseEvent<HTMLDivElement>) => void
  columns: readonly PcapColumnPref[]
  dataView: PcapDataView
  colorizePacketList: boolean
  colorSlot: number
  baseDescriptorIndex: number
  previousDescriptorIndex: number
}

const PacketRow = memo(function PacketRow({
  packetIndex,
  selected,
  marked,
  onSelect,
  onContextMenu,
  columns,
  dataView,
  colorizePacketList,
  colorSlot,
  baseDescriptorIndex,
  previousDescriptorIndex,
}: PacketRowProps) {
  const meta = getPacketRowMeta(packetIndex)
  const session = getPcapSession()
  const planPkt = session?.plan.packets[packetIndex]

  if (!meta.descriptor) return null
  const descriptor = meta.descriptor
  const visible = visibleColumns(columns)
  const gridTemplate = gridTemplateForColumns(columns)

  const endpoints = getPacketEndpoints(packetIndex, dataView)
  const protocols = getPacketProtocols(packetIndex)
  const baseDesc = session?.descriptors[baseDescriptorIndex]
  const prevDesc = previousDescriptorIndex >= 0 ? session?.descriptors[previousDescriptorIndex] : null
  const spans = session ? unifiedSpansForPacket(session.unifiedCoverage, packetIndex) : []
  const mark = marked ? 'M' : packetMark(meta, spans)
  const info = packetInfoWithPatches(meta, planPkt?.patches.length ?? 0, protocols)
  const hasIssue =
    (meta.summary?.issues.length ?? 0) > 0 ||
    (meta.discovery?.issues.length ?? 0) > 0 ||
    spans.some((s) => s.status === 'malformed' || s.status === 'unsupported')

  const changedHighlight = meta.changed
  const showColor = colorizePacketList && colorSlot !== NO_COLOR_SLOT

  return (
    <div
      data-selected={selected ? 'true' : undefined}
      data-color-slot={showColor ? String(colorSlot) : undefined}
      aria-selected={selected}
      className={`pcap-row${selected ? ' pcap-row--selected' : ''}${meta.changed ? ' pcap-row--changed' : ''}${changedHighlight ? ' pcap-row--highlight-changes' : ''}${hasIssue ? ' pcap-row--issue' : ''}${marked ? ' pcap-row--marked' : ''}${dataView === 'original' ? ' pcap-row--original-view' : ''}`}
      style={{ height: ROW_HEIGHT, gridTemplateColumns: gridTemplate }}
      role="row"
      data-packet-index={packetIndex}
      onClick={() => onSelect(packetIndex)}
      onContextMenu={(e) => onContextMenu(packetIndex, e)}
    >
      {visible.map((col) => (
        <Cell key={col.id} col={col.id} {...{
          mark,
          descriptor,
          baseDesc,
          prevDesc,
          endpoints,
          meta,
          info,
          protocols,
        }} />
      ))}
    </div>
  )
})

function Cell({
  col,
  mark,
  descriptor,
  baseDesc,
  prevDesc,
  endpoints,
  meta: _meta,
  info,
  protocols,
}: {
  col: PcapColumnId
  mark: string
  descriptor: PacketRecordDescriptor
  baseDesc: PacketRecordDescriptor | undefined
  prevDesc: PacketRecordDescriptor | null | undefined
  endpoints: { source: string; dest: string }
  meta: ReturnType<typeof getPacketRowMeta>
  info: string
  protocols: readonly string[]
}) {
  void _meta
  switch (col) {
    case 'mark':
      return (
        <span className="pcap-row__mark" role="gridcell" aria-hidden title={mark || undefined}>
          {mark}
        </span>
      )
    case 'no':
      return <span className="pcap-row__no" role="gridcell">{descriptor.packetNumber}</span>
    case 'time':
      return (
        <span className="pcap-row__time">
          {baseDesc ? relativeTimeSeconds(descriptor, baseDesc) : formatTimestamp(descriptor.timestamp)}
        </span>
      )
    case 'delta':
      return (
        <span className="pcap-row__delta">
          {prevDesc ? deltaFromPrevious(descriptor, prevDesc) : '0.000000'}
        </span>
      )
    case 'source':
      return <span className="pcap-row__source">{endpoints.source}</span>
    case 'dest':
      return <span className="pcap-row__dest">{endpoints.dest}</span>
    case 'protocol':
      return <span className="pcap-row__proto">{highestProtocol(protocols)}</span>
    case 'length':
      return <span className="pcap-row__len">{descriptor.capturedLength}</span>
    case 'info':
      return <span className="pcap-row__info">{info}</span>
    default:
      return null
  }
}

export function PcapPacketTables({
  dataView: dataViewProp,
  filteredIndices: filteredIndicesProp,
  scrollTop: scrollTopProp,
  onScrollTop,
  testId = 'pcap-packet-grid',
}: PcapPacketTablesProps = {}) {
  const storeFilteredIndices = usePcapStore((s) => s.filteredIndices)
  const selectedPacketIndex = usePcapStore((s) => s.selectedPacketIndex)
  const setSelectedPacketIndex = usePcapStore((s) => s.setSelectedPacketIndex)
  const storeScrollTop = usePcapStore((s) => s.scrollTop)
  const setScrollTop = usePcapStore((s) => s.setScrollTop)
  const epoch = usePcapStore((s) => s.sessionEpoch)
  const columns = usePcapStore((s) => s.columns)
  const setColumns = usePcapStore((s) => s.setColumns)
  const storeDataView = usePcapStore((s) => s.dataView)
  const markedPackets = usePcapStore((s) => s.markedPackets)
  const pushSelectionSnapshot = usePcapStore((s) => s.pushSelectionSnapshot)
  const setRevealFilteredCounterpart = usePcapStore((s) => s.setRevealFilteredCounterpart)
  const compareLayout = usePcapStore((s) => s.compareLayout)
  const setColoringRules = usePcapStore((s) => s.setColoringRules)
  const setColoringRulesDialogOpen = usePcapStore((s) => s.setColoringRulesDialogOpen)
  const colorizePacketList = usePcapStore((s) => s.colorizePacketList)
  const colorSlotsOriginal = usePcapStore((s) => s.colorSlotsOriginal)
  const colorSlotsAnonymized = usePcapStore((s) => s.colorSlotsAnonymized)
  const coloringRules = usePcapStore((s) => s.coloringRules)
  const coloringRulesRevision = usePcapStore((s) => s.coloringRulesRevision)
  const colorizeConversation = usePcapStore((s) => s.colorizeConversation)
  const resetTemporaryConversationColors = usePcapStore((s) => s.resetTemporaryConversationColors)

  const dataView = dataViewProp ?? storeDataView
  const filteredIndices = filteredIndicesProp ?? storeFilteredIndices
  const restoredScrollTop = scrollTopProp ?? storeScrollTop
  const colorSlots = dataView === 'original' ? colorSlotsOriginal : colorSlotsAnonymized
  const persistScrollTop = onScrollTop ?? setScrollTop

  const rootRef = useRef<HTMLDivElement>(null)
  const viewportRef = useRef<HTMLDivElement>(null)
  const headerRef = useRef<HTMLDivElement>(null)
  const filteredIndicesRef = useRef(filteredIndices)
  filteredIndicesRef.current = filteredIndices

  // Live virtualization scroll — local state; Zustand only on settle (cheap + smooth).
  const [liveScrollTop, setLiveScrollTop] = useState(restoredScrollTop)
  const liveScrollTopRef = useRef(liveScrollTop)
  const persistTimerRef = useRef(0)
  const rafVirtualRef = useRef(0)
  const pendingVirtualTopRef = useRef<number | null>(null)
  const lastVirtualStartRef = useRef(virtualWindowStart(restoredScrollTop, filteredIndices.length))

  useEffect(() => {
    if (Math.abs(restoredScrollTop - liveScrollTopRef.current) > 1) {
      liveScrollTopRef.current = restoredScrollTop
      lastVirtualStartRef.current = virtualWindowStart(restoredScrollTop, filteredIndices.length)
      setLiveScrollTop(restoredScrollTop)
      const el = viewportRef.current
      if (el && Math.abs(el.scrollTop - restoredScrollTop) > 1) el.scrollTop = restoredScrollTop
    }
  }, [restoredScrollTop, dataView, filteredIndices.length])

  const scheduleVirtualScroll = useCallback(
    (top: number, opts?: { persist?: boolean; force?: boolean }) => {
      liveScrollTopRef.current = top
      const nextStart = virtualWindowStart(top, filteredIndicesRef.current.length)
      const windowChanged = nextStart !== lastVirtualStartRef.current
      if (windowChanged || opts?.force) {
        lastVirtualStartRef.current = nextStart
        pendingVirtualTopRef.current = top
        if (!rafVirtualRef.current) {
          rafVirtualRef.current = requestAnimationFrame(() => {
            rafVirtualRef.current = 0
            const t = pendingVirtualTopRef.current
            pendingVirtualTopRef.current = null
            if (t !== null) setLiveScrollTop(t)
          })
        }
      }
      if (opts?.persist !== false) {
        window.clearTimeout(persistTimerRef.current)
        persistTimerRef.current = window.setTimeout(() => {
          persistScrollTop(liveScrollTopRef.current)
        }, 120)
      }
    },
    [persistScrollTop],
  )

  useEffect(
    () => () => {
      window.clearTimeout(persistTimerRef.current)
      if (rafVirtualRef.current) cancelAnimationFrame(rafVirtualRef.current)
    },
    [],
  )

  const compiled = useMemo(
    () => compileColoringRules(coloringRules, coloringRulesRevision).rules,
    [coloringRules, coloringRulesRevision],
  )
  const [viewportHeight] = useViewportHeight(viewportRef)
  const [dragCol, setDragCol] = useState<PcapColumnId | null>(null)
  const [contextMenu, setContextMenu] = useState<{ packetIndex: number; x: number; y: number } | null>(null)

  useEffect(() => {
    const el = rootRef.current
    if (!el) return
    applyColorPaletteToElement(el, compiled)
  }, [compiled])

  const session = epoch >= 0 ? getPcapSession() : null

  const count = filteredIndices.length
  const { start, end } = useVirtualWindow(liveScrollTop, viewportHeight, count)
  const totalHeight = count * ROW_HEIGHT
  const visible = visibleColumns(columns)
  const gridTemplate = gridTemplateForColumns(columns)

  const baseDescriptorIndex = filteredIndices[0] ?? 0

  const onSelect = useCallback(
    (packetIndex: number) => {
      setSelectedPacketIndex(packetIndex)
      setRevealFilteredCounterpart(false)
      pushSelectionSnapshot({ packetIndex, fieldPath: null, byteOffset: null })
    },
    [setSelectedPacketIndex, pushSelectionSnapshot, setRevealFilteredCounterpart],
  )

  const onRowContextMenu = useCallback((packetIndex: number, event: MouseEvent<HTMLDivElement>) => {
    event.preventDefault()
    setContextMenu({ packetIndex, x: event.clientX, y: event.clientY })
  }, [])

  useEffect(() => {
    if (compareLayout !== 'dual') return
    return registerPcapListScrollPane(dataView, {
      getFilteredIndices: () => filteredIndicesRef.current,
      getViewport: () => viewportRef.current,
      setLocalScrollTop: (top) => scheduleVirtualScroll(top, { persist: false }),
    })
  }, [compareLayout, dataView, scheduleVirtualScroll])

  useEffect(() => {
    const el = viewportRef.current
    if (!el) return
    const pos = filteredIndices.indexOf(selectedPacketIndex)
    if (pos < 0) return
    const targetTop = pos * PCAP_LIST_ROW_HEIGHT
    let next = el.scrollTop
    if (targetTop < el.scrollTop) next = targetTop
    else if (targetTop + PCAP_LIST_ROW_HEIGHT > el.scrollTop + el.clientHeight) {
      next = targetTop + PCAP_LIST_ROW_HEIGHT - el.clientHeight
    }
    if (Math.abs(next - el.scrollTop) > 1) {
      el.scrollTop = next
      scheduleVirtualScroll(next, { force: true })
    }
  }, [selectedPacketIndex, filteredIndices, scheduleVirtualScroll])

  const syncHeaderScroll = useCallback(() => {
    const vp = viewportRef.current
    const hdr = headerRef.current
    if (vp && hdr) hdr.scrollLeft = vp.scrollLeft
  }, [])

  const onScroll = useCallback(() => {
    const el = viewportRef.current
    if (!el) return
    const top = el.scrollTop
    scheduleVirtualScroll(top, { persist: !isPcapListScrollEcho() })
    syncHeaderScroll()
    if (compareLayout === 'dual' && !isPcapListScrollEcho()) {
      onPcapListUserScroll(dataView, top)
    }
  }, [scheduleVirtualScroll, syncHeaderScroll, compareLayout, dataView])

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (count === 0) return
    const pos = filteredIndices.indexOf(selectedPacketIndex)
    let next = pos
    if (event.key === 'ArrowDown') next = Math.min(count - 1, Math.max(0, pos) + 1)
    else if (event.key === 'ArrowUp') next = Math.max(0, (pos < 0 ? 0 : pos) - 1)
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = count - 1
    else if (event.key === 'PageDown') next = Math.min(count - 1, Math.max(0, pos) + 20)
    else if (event.key === 'PageUp') next = Math.max(0, (pos < 0 ? 0 : pos) - 20)
    else return
    event.preventDefault()
    const idx = filteredIndices[next]!
    setSelectedPacketIndex(idx)
    const el = viewportRef.current
    if (el) {
      const targetTop = next * ROW_HEIGHT
      let scroll = el.scrollTop
      if (targetTop < el.scrollTop) scroll = targetTop
      else if (targetTop + ROW_HEIGHT > el.scrollTop + el.clientHeight) {
        scroll = targetTop + ROW_HEIGHT - el.clientHeight
      }
      if (Math.abs(scroll - el.scrollTop) > 1) {
        el.scrollTop = scroll
        scheduleVirtualScroll(scroll, { force: true })
        if (compareLayout === 'dual') onPcapListUserScroll(dataView, scroll)
      }
    }
  }

  const resizeColumn = (id: PcapColumnId, delta: number) => {
    setColumns(
      columns.map((c) =>
        c.id === id ? { ...c, width: Math.max(32, Math.min(480, c.width + delta)) } : c,
      ),
    )
  }

  const reorderColumn = (from: PcapColumnId, to: PcapColumnId) => {
    if (from === to) return
    const sorted = [...columns].sort((a, b) => a.order - b.order)
    const fromIdx = sorted.findIndex((c) => c.id === from)
    const toIdx = sorted.findIndex((c) => c.id === to)
    if (fromIdx < 0 || toIdx < 0) return
    const [moved] = sorted.splice(fromIdx, 1)
    sorted.splice(toIdx, 0, moved!)
    setColumns(sorted.map((c, i) => ({ ...c, order: i })))
  }

  if (!session) return null

  const contextCtx = contextMenu
    ? buildFilterContextFromSession(contextMenu.packetIndex, dataView)
    : null
  const contextConversationId = contextCtx ? conversationIdFromFilterContext(contextCtx) : null
  const createFromOptions = contextCtx
    ? buildCreateColoringRuleOptions(contextCtx, getPacketProtocols(contextMenu!.packetIndex))
    : []

  const createRuleFromDraft = (filter: string, name: string) => {
    const rule: PcapColoringRule = {
      id: `user-${Date.now()}`,
      name,
      enabled: true,
      priority: Math.max(0, ...coloringRules.map((r) => r.priority)) + 1,
      filter,
      light: { foreground: '#1a1a1a', background: '#d8e8f8' },
      dark: { foreground: '#f0f0f0', background: '#2a4058' },
      source: 'user',
    }
    setColoringRules([...coloringRules.filter((r) => r.source === 'user'), rule])
    setColoringRulesDialogOpen(true)
    setContextMenu(null)
  }

  const rows = []
  for (let i = start; i < end; i++) {
    const packetIndex = filteredIndices[i]!
    const previousDescriptorIndex = i > 0 ? filteredIndices[i - 1]! : -1
    rows.push(
      <PacketRow
        key={`${packetIndex}-${epoch}`}
        packetIndex={packetIndex}
        selected={packetIndex === selectedPacketIndex}
        marked={markedPackets.includes(packetIndex)}
        onSelect={onSelect}
        onContextMenu={onRowContextMenu}
        columns={columns}
        dataView={dataView}
        colorizePacketList={colorizePacketList}
        colorSlot={colorSlots[packetIndex] ?? NO_COLOR_SLOT}
        baseDescriptorIndex={baseDescriptorIndex}
        previousDescriptorIndex={previousDescriptorIndex}
      />,
    )
  }

  return (
    <div
      ref={rootRef}
      className="pcap-tables pcap-tables--single"
      role="grid"
      aria-label={cs.pcap.table.listLabel}
      aria-rowcount={count}
      aria-colcount={visible.length}
      tabIndex={0}
      data-testid={testId}
      onKeyDown={onKeyDown}
    >
      <div className="pcap-table__header-wrap" ref={headerRef} role="row">
        <div className="pcap-table__header" style={{ gridTemplateColumns: gridTemplate }} role="presentation">
          {visible.map((col) => (
            <ColumnHeader
              key={col.id}
              col={col}
              dragCol={dragCol}
              setDragCol={setDragCol}
              onResize={resizeColumn}
              onReorder={reorderColumn}
            />
          ))}
        </div>
      </div>
      <div
        className="pcap-table__viewport"
        ref={viewportRef}
        onScroll={onScroll}
        data-testid="pcap-table-viewport"
        role="rowgroup"
        tabIndex={0}
        aria-label={cs.pcap.table.listLabel}
      >
        <div style={{ height: totalHeight, position: 'relative' }}>
          <div style={{ transform: `translateY(${start * ROW_HEIGHT}px)` }}>{rows}</div>
        </div>
      </div>
      {contextMenu ? (
        <div
          className="pcap-row-context-menu"
          style={{ top: contextMenu.y, left: contextMenu.x }}
          role="menu"
          data-testid="pcap-row-context-menu"
        >
          {createFromOptions.length > 0 ? (
            <>
              <p className="pcap-row-context-menu__label">{cs.pcap.coloring.createFrom}</p>
              {createFromOptions.map((opt) => (
                <button
                  key={opt.kind + opt.filter}
                  type="button"
                  role="menuitem"
                  className="pcap-row-context-menu__action"
                  data-testid={`pcap-create-color-rule-${opt.kind}`}
                  title={cs.pcap.coloring.createFromPreview.replace('{filter}', opt.filter)}
                  onClick={() => createRuleFromDraft(opt.filter, opt.name)}
                >
                  {opt.name}
                </button>
              ))}
            </>
          ) : null}
          {contextConversationId ? (
            <>
              <p className="pcap-row-context-menu__label">{cs.pcap.coloring.colorizeConversation}</p>
              <div className="pcap-row-context-menu__palette">
                {Array.from({ length: 10 }, (_, i) => (
                  <button
                    key={i}
                    type="button"
                    role="menuitem"
                    className="pcap-row-context-menu__swatch"
                    data-palette-index={i}
                    aria-label={cs.pcap.coloring.conversationSlot.replace('{n}', String(i + 1))}
                    onClick={() => {
                      colorizeConversation(contextMenu.packetIndex, i)
                      setContextMenu(null)
                    }}
                  />
                ))}
              </div>
              <button
                type="button"
                role="menuitem"
                className="pcap-row-context-menu__action"
                onClick={() => {
                  resetTemporaryConversationColors()
                  setContextMenu(null)
                }}
              >
                {cs.pcap.coloring.resetTemporary}
              </button>
            </>
          ) : null}
        </div>
      ) : null}
      {contextMenu ? (
        <button
          type="button"
          className="pcap-row-context-menu__backdrop"
          aria-label={cs.pcap.coloring.closeMenu}
          onClick={() => setContextMenu(null)}
        />
      ) : null}
    </div>
  )
}

function ColumnHeader({
  col,
  dragCol,
  setDragCol,
  onResize,
  onReorder,
}: {
  col: PcapColumnPref
  dragCol: PcapColumnId | null
  setDragCol: (id: PcapColumnId | null) => void
  onResize: (id: PcapColumnId, delta: number) => void
  onReorder: (from: PcapColumnId, to: PcapColumnId) => void
}) {
  const label = col.id === 'mark' ? '' : columnLabel(col.id)

  const onResizePointerDown = (event: PointerEvent<HTMLSpanElement>) => {
    event.preventDefault()
    event.stopPropagation()
    let lastX = event.clientX
    const onMove = (ev: globalThis.PointerEvent) => {
      const delta = ev.clientX - lastX
      lastX = ev.clientX
      onResize(col.id, delta)
    }
    const onUp = () => {
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', onUp)
    }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
  }

  return (
    <span
      className={`pcap-table__header-cell${dragCol === col.id ? ' is-dragging' : ''}`}
      draggable={col.id !== 'mark'}
      onDragStart={() => setDragCol(col.id)}
      onDragEnd={() => setDragCol(null)}
      onDragOver={(e: DragEvent) => e.preventDefault()}
      onDrop={() => {
        if (dragCol) onReorder(dragCol, col.id)
        setDragCol(null)
      }}
    >
      {label}
      {col.id !== 'info' ? (
        <span
          className="pcap-table__resize-handle"
          aria-hidden="true"
          onPointerDown={onResizePointerDown}
        />
      ) : null}
    </span>
  )
}

function useViewportHeight(ref: RefObject<HTMLDivElement | null>) {
  const [h, setH] = useState(320)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      const entry = entries[0]
      if (entry) setH(entry.contentRect.height)
    })
    ro.observe(el)
    setH(el.clientHeight)
    return () => ro.disconnect()
  }, [ref])
  return [h] as const
}
