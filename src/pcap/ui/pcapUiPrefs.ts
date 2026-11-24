/**
 * PCAP Wireshark-like UI preferences — localStorage only (step 1 + side-by-side + coloring).
 */

import type { PcapColoringRule } from '../coloring/types'
import { createDefaultColoringRules } from '../coloring/defaultRules'
import { COLORING_LIMITS } from '../coloring/types'
import { isValidSrgbColor, sanitizeColorPair } from '../coloring/colorValidation'

export type PcapDataView = 'original' | 'anonymized'
export type PcapWorkspaceLayout = 'desktop' | 'narrow'
export type PcapDetailBytesLayout = 'stacked' | 'side-by-side'
export type PcapNarrowPanel = 'list' | 'details' | 'bytes'

export type PcapColumnId =
  | 'mark'
  | 'no'
  | 'time'
  | 'delta'
  | 'source'
  | 'dest'
  | 'protocol'
  | 'length'
  | 'info'

export interface PcapColumnPref {
  readonly id: PcapColumnId
  readonly visible: boolean
  readonly width: number
  readonly order: number
}

export interface PcapUiPrefs {
  readonly dataView: PcapDataView
  readonly detailBytesLayout: PcapDetailBytesLayout
  readonly listPanelRatio: number
  readonly detailsPanelRatio: number
  /** Horizontal Original | Anonymized width ratio (left share). */
  readonly compareRatio: number
  /** When true, both panes share list/details/bytes vertical ratios. */
  readonly panelSizesLinked: boolean
  readonly columns: readonly PcapColumnPref[]
  readonly colorizePacketList: boolean
  readonly userColoringRules: readonly PcapColoringRule[]
}

const STORAGE_KEY = 'rnd-log-anonymizer:pref:pcapWiresharkUi'

export const DEFAULT_LIST_PANEL_RATIO = 0.42
export const DEFAULT_DETAILS_PANEL_RATIO = 0.55
export const MIN_PANEL_PX = 120

export {
  PCAP_DUAL_PANE_MIN_WIDTH,
  PCAP_FULL_COLUMNS_MIN_WIDTH,
  PCAP_COMPARE_RATIO_DEFAULT,
  PCAP_COMPARE_RATIO_MIN,
  PCAP_COMPARE_RATIO_MAX,
  PCAP_COMPARE_RATIO_STEP,
  clampCompareRatio,
  layoutFromWorkspaceWidth,
  type PcapCompareLayout,
  type PcapFocusedPane,
} from './pcapCompareLayout.ts'

import {
  PCAP_COMPARE_RATIO_DEFAULT,
  PCAP_FULL_COLUMNS_MIN_WIDTH,
  clampCompareRatio,
} from './pcapCompareLayout.ts'

export const DEFAULT_PCAP_COLUMNS: readonly PcapColumnPref[] = [
  { id: 'mark', visible: true, width: 24, order: 0 },
  { id: 'no', visible: true, width: 56, order: 1 },
  { id: 'time', visible: true, width: 96, order: 2 },
  { id: 'delta', visible: false, width: 72, order: 3 },
  { id: 'source', visible: true, width: 128, order: 4 },
  { id: 'dest', visible: true, width: 128, order: 5 },
  { id: 'protocol', visible: true, width: 80, order: 6 },
  { id: 'length', visible: true, width: 64, order: 7 },
  { id: 'info', visible: true, width: 240, order: 8 },
]

const DEFAULT_PREFS: PcapUiPrefs = {
  dataView: 'anonymized',
  detailBytesLayout: 'stacked',
  listPanelRatio: DEFAULT_LIST_PANEL_RATIO,
  detailsPanelRatio: DEFAULT_DETAILS_PANEL_RATIO,
  compareRatio: PCAP_COMPARE_RATIO_DEFAULT,
  panelSizesLinked: true,
  columns: DEFAULT_PCAP_COLUMNS,
  colorizePacketList: true,
  userColoringRules: [],
}

function cloneColumns(columns: readonly PcapColumnPref[]): PcapColumnPref[] {
  return columns.map((c) => ({ ...c }))
}

export function loadPcapUiPrefs(): PcapUiPrefs {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...DEFAULT_PREFS, columns: cloneColumns(DEFAULT_PCAP_COLUMNS) }
    const parsed = JSON.parse(raw) as Partial<PcapUiPrefs>
    return {
      dataView: parsed.dataView === 'original' ? 'original' : 'anonymized',
      detailBytesLayout: parsed.detailBytesLayout === 'side-by-side' ? 'side-by-side' : 'stacked',
      listPanelRatio:
        typeof parsed.listPanelRatio === 'number' && Number.isFinite(parsed.listPanelRatio)
          ? clamp(parsed.listPanelRatio, 0.18, 0.78)
          : DEFAULT_LIST_PANEL_RATIO,
      detailsPanelRatio:
        typeof parsed.detailsPanelRatio === 'number' && Number.isFinite(parsed.detailsPanelRatio)
          ? clamp(parsed.detailsPanelRatio, 0.2, 0.8)
          : DEFAULT_DETAILS_PANEL_RATIO,
      compareRatio:
        typeof parsed.compareRatio === 'number' && Number.isFinite(parsed.compareRatio)
          ? clampCompareRatio(parsed.compareRatio)
          : PCAP_COMPARE_RATIO_DEFAULT,
      panelSizesLinked: parsed.panelSizesLinked !== false,
      columns: normalizeColumns(parsed.columns),
      colorizePacketList: parsed.colorizePacketList !== false,
      userColoringRules: normalizeUserColoringRules(parsed.userColoringRules),
    }
  } catch {
    return { ...DEFAULT_PREFS, columns: cloneColumns(DEFAULT_PCAP_COLUMNS) }
  }
}

export function savePcapUiPrefs(prefs: PcapUiPrefs): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs))
  } catch {
    // ignore quota / private mode
  }
}

export function resetPcapColumnPrefs(): readonly PcapColumnPref[] {
  return cloneColumns(DEFAULT_PCAP_COLUMNS)
}

function normalizeColumns(input: readonly PcapColumnPref[] | undefined): PcapColumnPref[] {
  if (!input?.length) return cloneColumns(DEFAULT_PCAP_COLUMNS)
  const byId = new Map<PcapColumnId, PcapColumnPref>()
  for (const col of DEFAULT_PCAP_COLUMNS) byId.set(col.id, { ...col })
  for (const col of input) {
    if (!byId.has(col.id)) continue
    byId.set(col.id, {
      id: col.id,
      visible: col.visible !== false,
      width: typeof col.width === 'number' && col.width > 24 ? col.width : byId.get(col.id)!.width,
      order: typeof col.order === 'number' ? col.order : byId.get(col.id)!.order,
    })
  }
  return [...byId.values()].sort((a, b) => a.order - b.order)
}

function clamp(n: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, n))
}

export function mergeColoringRules(
  userRules: readonly PcapColoringRule[],
  temporaryRules: readonly PcapColoringRule[],
): readonly PcapColoringRule[] {
  const defaults = createDefaultColoringRules()
  const userIds = new Set(userRules.map((r) => r.id))
  const mergedDefaults = defaults.filter((d) => !userIds.has(d.id))
  return [...temporaryRules, ...userRules, ...mergedDefaults].map((r) => ({ ...r, light: { ...r.light }, dark: { ...r.dark } }))
}

function normalizeUserColoringRules(input: readonly PcapColoringRule[] | undefined): PcapColoringRule[] {
  if (!input?.length) return []
  const out: PcapColoringRule[] = []
  for (const raw of input.slice(0, COLORING_LIMITS.maxPersistentRules)) {
    if (!raw || typeof raw.id !== 'string' || typeof raw.filter !== 'string') continue
    if (raw.source === 'temporary-conversation') continue
    const name = typeof raw.name === 'string' ? raw.name.slice(0, COLORING_LIMITS.maxNameLength) : 'Rule'
    const filter = raw.filter.slice(0, COLORING_LIMITS.maxFilterBytes)
    const light = sanitizeColorPair({
      foreground: isValidSrgbColor(raw.light?.foreground ?? '') ? raw.light!.foreground : '#111111',
      background: isValidSrgbColor(raw.light?.background ?? '') ? raw.light!.background : '#f5f5f5',
    })
    const dark = sanitizeColorPair({
      foreground: isValidSrgbColor(raw.dark?.foreground ?? '') ? raw.dark!.foreground : '#f5f5f5',
      background: isValidSrgbColor(raw.dark?.background ?? '') ? raw.dark!.background : '#1f2937',
    })
    out.push({
      id: raw.id,
      name,
      enabled: raw.enabled !== false,
      priority: typeof raw.priority === 'number' ? raw.priority : 100,
      filter,
      light,
      dark,
      source: 'user',
    })
  }
  return out
}

export function visibleColumns(columns: readonly PcapColumnPref[]): readonly PcapColumnPref[] {
  return [...columns].filter((c) => c.visible).sort((a, b) => a.order - b.order)
}

/** Compact optional columns under full-column breakpoint (keep core Wireshark set). */
export function columnsForWorkspaceWidth(
  columns: readonly PcapColumnPref[],
  workspaceWidth: number,
): readonly PcapColumnPref[] {
  if (workspaceWidth >= PCAP_FULL_COLUMNS_MIN_WIDTH) return columns
  return columns.map((c) => (c.id === 'delta' ? { ...c, visible: false } : c))
}

export function gridTemplateForColumns(columns: readonly PcapColumnPref[]): string {
  return visibleColumns(columns)
    .map((c) => (c.id === 'info' ? `minmax(${c.width}px, 1fr)` : `${c.width}px`))
    .join(' ')
}

export function columnLabel(id: PcapColumnId): string {
  const labels: Record<PcapColumnId, string> = {
    mark: '',
    no: 'No.',
    time: 'Time',
    delta: 'Delta',
    source: 'Source',
    dest: 'Destination',
    protocol: 'Protocol',
    length: 'Length',
    info: 'Info',
  }
  return labels[id]
}
