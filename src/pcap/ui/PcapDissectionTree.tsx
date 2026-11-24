import { useCallback, useEffect, useMemo, useRef, type KeyboardEvent } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import type { DissectionNode } from '../dissection/types'
import { nodePath } from '../dissection/types'
import { protocolLabel } from './formatters.ts'
import type { PcapDataView } from './pcapUiPrefs.ts'
import { usePcapPanelScrollSync } from './pcapPanelScrollSync.tsx'

const EMPTY_ROOTS: readonly DissectionNode[] = []

export interface PcapDissectionTreeProps {
  readonly roots: readonly DissectionNode[]
  readonly loading?: boolean
  readonly dataView?: PcapDataView
}

export function PcapDissectionTree({ roots: rootsProp, loading = false, dataView: view }: PcapDissectionTreeProps) {
  const roots = rootsProp.length === 0 ? EMPTY_ROOTS : rootsProp
  const expandedTreeNodes = usePcapStore((s) => s.expandedTreeNodes)
  const selectedFieldPath = usePcapStore((s) => s.selectedFieldPath)
  const selectedByteOffset = usePcapStore((s) => s.selectedByteOffset)
  const toggleTreeNode = usePcapStore((s) => s.toggleTreeNode)
  const setSelectedFieldPath = usePcapStore((s) => s.setSelectedFieldPath)
  const setSelectedByteOffset = usePcapStore((s) => s.setSelectedByteOffset)
  const expandAllTreeNodes = usePcapStore((s) => s.expandAllTreeNodes)
  const selectedPacketIndex = usePcapStore((s) => s.selectedPacketIndex)
  const pushSelectionSnapshot = usePcapStore((s) => s.pushSelectionSnapshot)
  const treeRef = useRef<HTMLUListElement>(null)
  const viewport = useRef<HTMLDivElement>(null)
  const storeView = usePcapStore(s => s.dataView)
  const onScroll = usePcapPanelScrollSync({ channel: 'tree', dataView: view ?? storeView,
    viewport, enabled: !loading && roots.length > 0 })

  useEffect(() => {
    if (roots.length === 0 || expandedTreeNodes.length > 0) return
    expandAllTreeNodes(roots.map((r) => r.id))
  }, [roots, expandedTreeNodes.length, expandAllTreeNodes])

  const selectNode = useCallback(
    (node: DissectionNode) => {
      const path = nodePath(node, roots)
      setSelectedFieldPath(path)
      if (node.length > 0) setSelectedByteOffset(node.offset)
      pushSelectionSnapshot({
        packetIndex: selectedPacketIndex,
        fieldPath: path,
        byteOffset: node.length > 0 ? node.offset : null,
      })
    },
    [roots, selectedPacketIndex, setSelectedFieldPath, setSelectedByteOffset, pushSelectionSnapshot],
  )

  const visibleRows = useMemo(() => {
    const rows: { node: DissectionNode; depth: number; path: string }[] = []
    const walk = (nodes: readonly DissectionNode[], depth: number, prefix: string) => {
      for (const node of nodes) {
        const path = prefix ? `${prefix}/${node.id}` : node.id
        rows.push({ node, depth, path })
        if (node.children.length > 0 && expandedTreeNodes.includes(node.id)) {
          walk(node.children, depth + 1, path)
        }
      }
    }
    walk(roots, 0, '')
    return rows
  }, [roots, expandedTreeNodes])

  const focusedIndex = visibleRows.findIndex((r) => r.path === selectedFieldPath)

  const onKeyDown = (event: KeyboardEvent<HTMLUListElement>) => {
    if (visibleRows.length === 0) return
    const row = visibleRows[Math.max(0, focusedIndex)] ?? visibleRows[0]!
    if (event.key === 'ArrowRight') {
      event.preventDefault()
      if (row.node.children.length > 0) {
        if (!expandedTreeNodes.includes(row.node.id)) toggleTreeNode(row.node.id)
        else if (row.node.children[0]) selectNode(row.node.children[0]!)
      }
    } else if (event.key === 'ArrowLeft') {
      event.preventDefault()
      if (expandedTreeNodes.includes(row.node.id)) toggleTreeNode(row.node.id)
    } else if (event.key === 'ArrowDown') {
      event.preventDefault()
      const next = visibleRows[Math.min(visibleRows.length - 1, Math.max(0, focusedIndex) + 1)]
      if (next) selectNode(next.node)
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      const prev = visibleRows[Math.max(0, Math.max(0, focusedIndex) - 1)]
      if (prev) selectNode(prev.node)
    } else if (event.key === 'Enter') {
      event.preventDefault()
      if (row.node.children.length > 0) toggleTreeNode(row.node.id)
    }
  }

  if (loading) {
    return <p className="pcap-tree__loading">{cs.pcap.detail.loading}</p>
  }

  if (roots.length === 0) {
    return <p>{cs.pcap.detail.treeEmpty}</p>
  }

  return (
    <div className="pcap-dissection-tree-wrap" ref={viewport} onScroll={onScroll}>
      <ul
        ref={treeRef}
        className="pcap-tree pcap-dissection-tree"
        role="tree"
        aria-label={cs.pcap.detail.tree}
        tabIndex={0}
        data-testid="pcap-dissection-tree"
        onKeyDown={onKeyDown}
      >
        {visibleRows.map(({ node, depth, path }) => {
          const expanded = expandedTreeNodes.includes(node.id)
          const hasChildren = node.children.length > 0
          const selected = selectedFieldPath === path
          const byteSelected =
            selectedByteOffset !== null &&
            node.length > 0 &&
            selectedByteOffset >= node.offset &&
            selectedByteOffset < node.offset + node.length
          const changeClass =
            node.changeKind && node.changeKind !== 'none'
              ? ` pcap-tree__node--${node.changeKind}`
              : ''
          return (
            <li
              key={path}
              role="treeitem"
              aria-expanded={hasChildren ? expanded : undefined}
              aria-selected={selected || byteSelected ? true : undefined}
              className={`pcap-tree__node${selected || byteSelected ? ' pcap-tree__node--selected' : ''}${changeClass}`}
              style={{ paddingLeft: `${depth * 12 + 4}px` }}
              data-field-path={path}
              data-offset={node.offset}
              data-length={node.length}
              onClick={() => selectNode(node)}
            >
              {hasChildren ? (
                <button
                  type="button"
                  className="pcap-tree__toggle"
                  aria-label={expanded ? cs.pcap.detail.collapse : cs.pcap.detail.expand}
                  onClick={(e) => {
                    e.stopPropagation()
                    toggleTreeNode(node.id)
                  }}
                >
                  {expanded ? '▼' : '▶'}
                </button>
              ) : (
                <span className="pcap-tree__toggle pcap-tree__toggle--leaf" aria-hidden />
              )}
              <span className="pcap-tree__label">{protocolLabel(node.label)}</span>
              {node.displayValue ?? node.value ? (
                <span className="pcap-tree__value">{node.displayValue ?? node.value}</span>
              ) : null}
              {node.length > 0 ? (
                <span className="pcap-tree__meta" title={cs.pcap.detail.bytePositionHint}>
                  {cs.pcap.detail.patchMeta
                    .replace('{off}', String(node.offset))
                    .replace('{len}', String(node.length))}
                </span>
              ) : null}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
