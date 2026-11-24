import { useEffect, useMemo, useRef } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { getPacketRowMeta, getPcapSession } from './pcapSession.ts'
import { formatIpv4Bytes, formatMacBytes, protocolLabel } from './formatters.ts'
import { getPcapCoverageViewModel } from './getPcapCoverageViewModel.ts'
import type { PcapPlanPacket } from '../export/planSnapshot'
import type { PcapSpanCoverageRow } from '../coverage/pcapCoverageViewModel'
import { PcapDissectionTree } from './PcapDissectionTree.tsx'
import { usePacketDissection } from './usePacketDissection.ts'
import { usePacketPreview } from '../preview/usePacketPreview.ts'
import type { PcapDataView } from './pcapUiPrefs.ts'
import {
  findDeepestNodeAtOffset,
  flattenDissection,
  nodePath,
  type DissectionChangeKind,
  type DissectionNode,
} from '../dissection/types'
import type { BytePatch } from '../sanitize/types'
import { usePcapPanelScrollSync } from './pcapPanelScrollSync.tsx'

const EMPTY_DISSECTION_ROOTS: readonly DissectionNode[] = []

export interface PcapPacketDetailsProps {
  readonly dataView?: PcapDataView
}

/**
 * Packet inspector — Wireshark-style dissection is the primary view.
 * Concrete anonymization diffs live on a sibling tab so both get full panel height
 * instead of fighting in a nested accordion.
 */
export function PcapPacketDetails({ dataView: dataViewProp }: PcapPacketDetailsProps = {}) {
  const selectedPacketIndex = usePcapStore((s) => s.selectedPacketIndex)
  const sessionEpoch = usePcapStore((s) => s.sessionEpoch)
  const storeDataView = usePcapStore((s) => s.dataView)
  const dataView = dataViewProp ?? storeDataView
  const meta = getPacketRowMeta(selectedPacketIndex)
  const vm = getPcapCoverageViewModel()
  const spanRows = vm?.spansForPacket(selectedPacketIndex) ?? []
  const session = getPcapSession()
  const planPkt = session?.plan.packets[selectedPacketIndex]
  const { dissection, loading } = usePacketDissection(selectedPacketIndex, sessionEpoch, dataView)
  const { preview } = usePacketPreview(selectedPacketIndex, sessionEpoch)
  const detailTab = usePcapStore(s => s.detailTab)
  const tab = detailTab === 'changes' ? 'changes' : 'tree'
  const setTab = usePcapStore(s => s.setDetailTab)
  const expandAllTreeNodes = usePcapStore((s) => s.expandAllTreeNodes)
  const collapseAllTreeNodes = usePcapStore((s) => s.collapseAllTreeNodes)

  const treeExpandableIds = useMemo(() => {
    const roots = dissection?.roots ?? []
    if (roots.length === 0) return [] as string[]
    return flattenDissection(roots)
      .filter((n) => n.children.length > 0)
      .map((n) => n.id)
  }, [dissection])

  const concrete = useMemo(
    () =>
      buildConcreteChanges({
        patches: planPkt?.patches ?? [],
        roots: dissection?.roots ?? [],
        originalBytes: preview?.original.data,
        anonymizedBytes: preview?.anonymizedBytes,
      }),
    [planPkt?.patches, dissection, preview],
  )

  const dispositionRows = useMemo(
    () =>
      spanRows.filter(
        (c) =>
          c.exportAction === 'mapped'
          || c.exportAction === 'redacted'
          || c.exportAction === 'masked-content'
          || c.exportAction === 'preserved-for-diagnostics'
          || c.needsAttention,
      ),
    [spanRows],
  )

  const changeCount =
    concrete.length > 0
      ? concrete.length + (planPkt?.truncatedLength !== undefined ? 1 : 0)
      : dispositionRows.length + (planPkt?.truncatedLength !== undefined ? 1 : 0)

  const showChangesTab =
    concrete.length > 0
    || dispositionRows.length > 0
    || planPkt?.truncatedLength !== undefined
    || (planPkt?.patches.length ?? 0) > 0

  useEffect(() => {
    if (!showChangesTab && tab === 'changes') setTab('tree')
  }, [showChangesTab, tab, setTab])

  if (!meta.descriptor) {
    return (
      <section className="pcap-details-panel pcap-details-panel--empty" data-testid="pcap-packet-details">
        <p>{cs.pcap.detail.none}</p>
      </section>
    )
  }

  const patchCount = planPkt?.patches.length ?? 0

  return (
    <section
      className="pcap-details-panel"
      data-testid="pcap-packet-details"
      data-data-view={dataView}
      data-detail-tab={tab}
      aria-label={cs.pcap.detail.label}
    >
      <header className="pcap-details-panel__header">
        <div className="pcap-details-panel__title-block">
          <h3>
            {cs.pcap.detail.packetTitle.replace('{n}', String(meta.descriptor.packetNumber))}
          </h3>
          {patchCount > 0 ? (
            <p className="pcap-details-panel__subtitle">
              {cs.pcap.detail.packetChangesMeta.replace('{n}', String(patchCount))}
            </p>
          ) : null}
        </div>
        {tab === 'tree' && treeExpandableIds.length > 0 ? (
          <div className="pcap-details-panel__tree-actions" role="group" aria-label={cs.pcap.detail.tree}>
            <button
              type="button"
              className="btn btn--tiny"
              data-testid="pcap-tree-expand-all"
              onClick={() => expandAllTreeNodes(treeExpandableIds)}
            >
              {cs.pcap.detail.expandAll}
            </button>
            <button
              type="button"
              className="btn btn--tiny"
              data-testid="pcap-tree-collapse-all"
              onClick={collapseAllTreeNodes}
            >
              {cs.pcap.detail.collapseAll}
            </button>
          </div>
        ) : null}
        <div
          className="pcap-details-panel__tabs"
          role="tablist"
          aria-label={cs.pcap.detail.tabs}
        >
          <button
            type="button"
            role="tab"
            id="pcap-detail-tab-tree"
            aria-selected={tab === 'tree'}
            aria-controls="pcap-detail-panel-tree"
            className={tab === 'tree' ? 'is-active' : undefined}
            data-testid="pcap-detail-tab-tree"
            onClick={() => setTab('tree')}
          >
            {cs.pcap.detail.tree}
          </button>
          {showChangesTab ? (
            <button
              type="button"
              role="tab"
              id="pcap-detail-tab-changes"
              aria-selected={tab === 'changes'}
              aria-controls="pcap-detail-panel-changes"
              className={tab === 'changes' ? 'is-active' : undefined}
              data-testid="pcap-detail-tab-changes"
              onClick={() => setTab('changes')}
            >
              {cs.pcap.detail.changes}
              {changeCount > 0 ? (
                <span className="pcap-details-panel__tab-badge">{changeCount}</span>
              ) : null}
            </button>
          ) : null}
        </div>
      </header>

      <div className="pcap-details-panel__body">
        {tab === 'tree' ? (
          <div
            className="pcap-details-panel__pane"
            role="tabpanel"
            id="pcap-detail-panel-tree"
            aria-labelledby="pcap-detail-tab-tree"
            data-testid="pcap-detail-panel-tree"
          >
            <PcapDissectionTree roots={dissection?.roots ?? EMPTY_DISSECTION_ROOTS} loading={loading} dataView={dataView} />
          </div>
        ) : (
          <div
            className="pcap-details-panel__pane pcap-details-panel__changes-pane"
            role="tabpanel"
            id="pcap-detail-panel-changes"
            aria-labelledby="pcap-detail-tab-changes"
            data-testid="pcap-packet-disposition"
          >
            <ChangesPane
              dataView={dataView}
              concrete={concrete}
              dispositionRows={dispositionRows}
              planPkt={planPkt}
              onSelectChange={(row) => {
                usePcapStore.getState().setSelectedByteOffset(row.offset)
                if (row.path) usePcapStore.getState().setSelectedFieldPath(row.path)
                setTab('tree')
              }}
            />
          </div>
        )}
      </div>
    </section>
  )
}

function ChangesPane({
  dataView,
  concrete,
  dispositionRows,
  planPkt,
  onSelectChange,
}: {
  dataView: PcapDataView
  concrete: readonly ConcreteChangeRow[]
  dispositionRows: readonly PcapSpanCoverageRow[]
  planPkt: PcapPlanPacket | undefined
  onSelectChange: (row: ConcreteChangeRow) => void
}) {
  const viewport = useRef<HTMLDivElement>(null)
  const onScroll = usePcapPanelScrollSync({ channel: 'changes', dataView, viewport })
  return (
    <>
      <p className="pcap-details-panel__changes-lead">{cs.pcap.detail.changesLead}</p>
      <div className="pcap-details-panel__changes-scroll" ref={viewport} onScroll={onScroll}>
      {concrete.length > 0 ? (
        <ul className="pcap-detail__list pcap-detail__list--concrete" data-testid="pcap-packet-concrete-changes">
          {concrete.map((row) => (
            <li key={row.key} data-disposition={row.action}>
              <button
                type="button"
                className="pcap-detail__change-btn"
                onClick={() => onSelectChange(row)}
              >
                <span className="pcap-detail__change-main">
                  <span className="pcap-detail__proto">{row.label}</span>
                  <span className="pcap-detail__values">
                    <span className="pcap-detail__before" title={row.before}>{row.before}</span>
                    <span className="pcap-detail__arrow" aria-hidden>
                      {cs.pcap.detail.changeArrow}
                    </span>
                    <span className="pcap-detail__after" title={row.after}>{row.after}</span>
                  </span>
                </span>
                <span className="pcap-detail__change-side">
                  <span className="pcap-detail__meta">
                    {cs.pcap.detail.patchMeta
                      .replace('{off}', String(row.offset))
                      .replace('{len}', String(row.length))}
                  </span>
                  <span className={`pcap-detail__action pcap-detail__action--${row.action}`}>
                    {row.actionLabel}
                  </span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      ) : dispositionRows.length > 0 ? (
        <ul className="pcap-detail__list">
          {dispositionRows.map((c, i) => (
            <li key={`d-${i}`} data-disposition={c.exportAction}>
              <span className="pcap-detail__proto">{protocolLabel(c.protocol)}</span>
              <span className={`pcap-detail__action pcap-detail__action--${c.exportAction}`}>
                {c.exportActionLabel}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="pcap-detail__empty">{cs.pcap.detail.noChanges}</p>
      )}

      {planPkt?.truncatedLength !== undefined ? (
        <ul className="pcap-detail__list">
          <li data-disposition="truncated">
            <span className="pcap-detail__proto">{cs.pcap.detail.truncated}</span>
            <span className="pcap-detail__action pcap-detail__action--truncated">
              {cs.pcap.detail.payloadTruncated.replace('{len}', String(planPkt.truncatedLength))}
            </span>
          </li>
        </ul>
      ) : null}

      {planPkt?.changeCounts ? (
        <p className="pcap-details-panel__changes-counts" data-testid="pcap-packet-change-counts">
          <span>mapped {planPkt.changeCounts.mapped}</span>
          <span>redacted {planPkt.changeCounts.redacted}</span>
          <span>masked {planPkt.changeCounts['masked-content']}</span>
          <span>diagnostics {planPkt.changeCounts['preserved-for-diagnostics']}</span>
        </p>
      ) : null}
      </div>
    </>
  )
}

interface ConcreteChangeRow {
  readonly key: string
  readonly label: string
  readonly before: string
  readonly after: string
  readonly offset: number
  readonly length: number
  readonly action: string
  readonly actionLabel: string
  readonly path: string | null
}

function buildConcreteChanges(input: {
  patches: readonly BytePatch[]
  roots: readonly DissectionNode[]
  originalBytes: Uint8Array | undefined
  anonymizedBytes: Uint8Array | undefined
}): ConcreteChangeRow[] {
  if (input.patches.length === 0) return []
  const flat = flattenDissection(input.roots)
  const out: ConcreteChangeRow[] = []

  for (const patch of input.patches) {
    const len = patch.data.length
    if (len <= 0) continue
    const node = bestNodeForPatch(input.roots, flat, patch.offset, len)
    const beforeBytes = input.originalBytes?.subarray(patch.offset, patch.offset + len)
    const afterBytes =
      input.anonymizedBytes?.subarray(patch.offset, patch.offset + len) ?? patch.data
    const kind = (node?.changeKind && node.changeKind !== 'none'
      ? node.changeKind
      : guessActionFromBytes(beforeBytes, afterBytes)) as DissectionChangeKind | 'rewritten'
    const action = actionKeyForKind(kind)
    out.push({
      key: `${patch.offset}:${len}`,
      label: node
        ? (node.fieldName || node.label || cs.pcap.detail.patchAt.replace('{off}', String(patch.offset)))
        : cs.pcap.detail.patchAt.replace('{off}', String(patch.offset)),
      before: formatChangeBytes(beforeBytes),
      after: formatChangeBytes(afterBytes),
      offset: patch.offset,
      length: len,
      action,
      actionLabel: actionLabelForKey(action),
      path: node ? nodePath(node, input.roots) : null,
    })
  }
  return out
}

function bestNodeForPatch(
  roots: readonly DissectionNode[],
  flat: readonly DissectionNode[],
  offset: number,
  length: number,
): DissectionNode | null {
  const end = offset + length
  let best: DissectionNode | null = null
  let bestScore = Infinity
  for (const n of flat) {
    if (n.length <= 0) continue
    const nEnd = n.offset + n.length
    if (nEnd <= offset || n.offset >= end) continue
    const exact = n.offset === offset && n.length === length
    const score = exact ? 0 : n.length
    if (score < bestScore) {
      best = n
      bestScore = score
    }
  }
  return best ?? findDeepestNodeAtOffset(roots, offset)
}

function formatChangeBytes(bytes: Uint8Array | undefined): string {
  if (!bytes || bytes.length === 0) return '—'
  if (bytes.length === 6) return formatMacBytes(bytes, 0)
  if (bytes.length === 4) return formatIpv4Bytes(bytes, 0)
  if (bytes.length === 16) return formatIpv6Compact(bytes)
  const max = 12
  const hex = Array.from(bytes.subarray(0, Math.min(bytes.length, max)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(' ')
  return bytes.length > max ? `${hex}…` : hex
}

function formatIpv6Compact(bytes: Uint8Array): string {
  const parts: string[] = []
  for (let i = 0; i < 16; i += 2) {
    parts.push(((bytes[i]! << 8) | bytes[i + 1]!).toString(16))
  }
  return parts.join(':')
}

function guessActionFromBytes(
  before: Uint8Array | undefined,
  after: Uint8Array,
): DissectionChangeKind {
  if (!before) return 'rewritten'
  let allZeroOrStar = true
  for (let i = 0; i < after.length; i++) {
    const b = after[i]!
    if (b !== 0 && b !== 0x2a && b !== 0x2d) {
      allZeroOrStar = false
      break
    }
  }
  if (allZeroOrStar) return 'masked'
  return 'mapped'
}

function actionKeyForKind(kind: DissectionChangeKind | 'rewritten'): string {
  switch (kind) {
    case 'mapped':
      return 'mapped'
    case 'redacted':
    case 'masked':
      return 'masked-content'
    case 'preserved-for-diagnostics':
      return 'preserved-for-diagnostics'
    case 'truncated':
      return 'truncated'
    case 'uncovered':
      return 'blocked'
    default:
      return 'mapped'
  }
}

function actionLabelForKey(action: string): string {
  const labels = cs.pcap.coverageUx.exportAction as Record<string, string>
  return labels[action] ?? action
}
