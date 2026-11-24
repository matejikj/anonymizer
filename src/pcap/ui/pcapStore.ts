/**
 * PCAP UI store — session-scoped view state (step 1 Wireshark layout).
 */

import { create } from 'zustand'
import {
  DEFAULT_PCAP_FILTER,
  type PcapFilterState,
  type PcapPhase,
} from './pcapSession'
import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel'
import {
  DEFAULT_PCAP_LEVEL,
  derivedPolicyView,
  presetToSanitizationPolicy,
} from '../profile/presets'
import type { SanitizationPolicy } from '../sanitize/types'
import type { DerivedPcapPolicyView } from '../profile/presets'
import {
  loadPcapUiPrefs,
  savePcapUiPrefs,
  resetPcapColumnPrefs,
  mergeColoringRules,
  type PcapColumnPref,
  type PcapDataView,
  type PcapDetailBytesLayout,
  type PcapNarrowPanel,
  type PcapUiPrefs,
  type PcapWorkspaceLayout,
  type PcapCompareLayout,
  type PcapFocusedPane,
  clampCompareRatio,
} from './pcapUiPrefs'
import type { PcapColoringRule } from '../coloring/types'
import { nextColoringRulesRevision } from '../coloring/compileColoringRules'
import {
  CONVERSATION_PALETTE,
  conversationIdFromFilterContext,
} from '../coloring/conversation'
import { buildFilterContextFromSession } from './pcapSession'
import {
  pushSelectionHistory,
  navigateSelectionHistory as navHistory,
} from './pcapSelectionHistory'
import type { ParseStatus } from '../displayFilter'

export type PcapDetailTab = 'changes' | 'tree' | 'hex'
export type PcapInspectorTab = 'overview' | 'entities' | 'coverage' | 'profile' | 'shared'

export interface PcapProgress {
  phase: 'idle' | 'checking' | 'analyzing' | 'building' | 'coverage'
  packetsDone: number
  packetsTotal: number
  bytesDone: number
  bytesTotal: number
  startedAt: number
  cancellable: boolean
  fileName: string | null
}

export function createIdlePcapProgress(): PcapProgress {
  return {
    phase: 'idle',
    packetsDone: 0,
    packetsTotal: 0,
    bytesDone: 0,
    bytesTotal: 0,
    startedAt: 0,
    cancellable: false,
    fileName: null,
  }
}

export type PcapExportPhase = 'idle' | 'exporting' | 'done' | 'cancelled' | 'error'
export type PcapReplaceDialog = 'none' | 'open'

export interface PcapDisplayFilterError {
  readonly message: string
  readonly offset: number
}

export interface TemporaryConversationColor {
  readonly conversationId: string
  readonly paletteIndex: number
  readonly rule: PcapColoringRule
}

export interface PcapUiState {
  phase: PcapPhase
  sessionEpoch: number
  progress: PcapProgress
  errorMessage: string | null
  selectedPacketIndex: number
  filter: PcapFilterState
  displayFilterDraft: string
  displayFilterApplied: string
  displayFilterStatus: ParseStatus | 'empty'
  displayFilterError: PcapDisplayFilterError | null
  displayFilterHistory: readonly string[]
  filteredIndices: number[]
  filteredIndicesOriginal: number[]
  filteredIndicesAnonymized: number[]
  selectedFieldPath: string | null
  selectedByteOffset: number | null
  activeByteSourceId: string
  expandedTreeNodes: readonly string[]
  markedPackets: readonly number[]
  selectionHistory: readonly { packetIndex: number; fieldPath: string | null; byteOffset: number | null }[]
  selectionHistoryIndex: number
  detailTab: PcapDetailTab
  inspectorTab: PcapInspectorTab
  inspectorOpen: boolean
  layoutMode: PcapWorkspaceLayout
  narrowPanel: PcapNarrowPanel
  /** dual = side-by-side Original|Anonymized; single = switchable (narrow workspace). */
  compareLayout: PcapCompareLayout
  focusedPane: PcapFocusedPane
  compareRatio: number
  panelSizesLinked: boolean
  workspaceWidth: number
  dataView: PcapDataView
  detailBytesLayout: PcapDetailBytesLayout
  listPanelRatio: number
  detailsPanelRatio: number
  columns: readonly PcapColumnPref[]
  colorizePacketList: boolean
  coloringRules: readonly PcapColoringRule[]
  coloringRulesRevision: number
  temporaryConversationSlots: readonly TemporaryConversationColor[]
  colorSlotsOriginal: Uint16Array
  colorSlotsAnonymized: Uint16Array
  colorSlotsRevision: number
  coloringRulesDialogOpen: boolean
  recoverySearchDialogOpen: boolean
  /** T10 — closable anonymization outcome dialog after analysis (cs: Výsledek anonymizace). */
  outcomeDialogOpen: boolean
  scrollTop: number
  /** Pane-local scroll anchors (preserved across dual↔single). */
  scrollTopOriginal: number
  scrollTopAnonymized: number
  revealFilteredCounterpart: boolean
  liveAnnounce: string
  /** Top-visible packet index from the scroll leader pane (dual sync). */
  scrollAnchorPacketIndex: number | null
  scrollAnchorLeader: PcapFocusedPane | null
  activePcapLevel: PcapAnonymizationLevel
  requestedPcapLevel: PcapAnonymizationLevel | null
  activePolicy: SanitizationPolicy
  /** @deprecated Compatibility for UI still reading profile-shaped view. */
  activeProfile: DerivedPcapPolicyView
  /** @deprecated */
  activeProfileId: string
  /** @deprecated Always false — no editable PCAP profile. */
  profileDirty: boolean
  profileEpoch: number
  replaceDialog: PcapReplaceDialog
  pendingReplaceFileName: string | null
  planGeneration: number
  activePlanGeneration: number
  planStale: boolean
  entityCategoryFilter: string
  entityQuery: string
  helpTopic: string | null
  exportHint: string | null
  exportBusy: boolean
  exportPhase: PcapExportPhase
  exportMessage: string | null
  exportPacketsDone: number
  exportPacketsTotal: number
  exportStartedAt: number
  setPhase: (phase: PcapPhase) => void
  bumpSessionEpoch: () => void
  setProgress: (progress: PcapProgress) => void
  patchProgress: (patch: Partial<PcapProgress>) => void
  setErrorMessage: (message: string | null) => void
  setSelectedPacketIndex: (index: number) => void
  setFilter: (filter: Partial<PcapFilterState>) => void
  setDisplayFilterDraft: (draft: string, status: ParseStatus | 'empty', error: PcapDisplayFilterError | null) => void
  applyDisplayFilter: (expression: string) => void
  clearDisplayFilter: () => void
  revertDisplayFilterDraft: () => void
  setFilteredIndices: (indices: number[]) => void
  setFilteredIndicesForViews: (original: number[], anonymized: number[]) => void
  setSelectedFieldPath: (path: string | null) => void
  setSelectedByteOffset: (offset: number | null) => void
  setActiveByteSourceId: (id: string) => void
  toggleTreeNode: (nodeId: string) => void
  setExpandedTreeNodes: (nodes: readonly string[]) => void
  expandAllTreeNodes: (nodeIds: readonly string[]) => void
  collapseAllTreeNodes: () => void
  toggleMarkedPacket: (packetIndex: number) => void
  pushSelectionSnapshot: (snapshot: { packetIndex: number; fieldPath: string | null; byteOffset: number | null }) => void
  navigateSelectionHistory: (direction: -1 | 1) => void
  setDetailTab: (tab: PcapDetailTab) => void
  setInspectorTab: (tab: PcapInspectorTab) => void
  setInspectorOpen: (open: boolean) => void
  setLayoutMode: (mode: PcapWorkspaceLayout) => void
  setNarrowPanel: (panel: PcapNarrowPanel) => void
  setCompareLayout: (layout: PcapCompareLayout) => void
  setFocusedPane: (pane: PcapFocusedPane) => void
  setCompareRatio: (ratio: number, opts?: { persist?: boolean }) => void
  setPanelSizesLinked: (linked: boolean) => void
  setWorkspaceWidth: (width: number) => void
  setDataView: (view: PcapDataView) => void
  setDetailBytesLayout: (layout: PcapDetailBytesLayout) => void
  setListPanelRatio: (ratio: number) => void
  setDetailsPanelRatio: (ratio: number) => void
  setColumns: (columns: readonly PcapColumnPref[]) => void
  resetColumns: () => void
  setColorizePacketList: (on: boolean) => void
  setColoringRules: (rules: readonly PcapColoringRule[]) => void
  resetColoringRulesToDefaults: () => void
  setColoringRulesDialogOpen: (open: boolean) => void
  setOutcomeDialogOpen: (open: boolean) => void
  setRecoverySearchDialogOpen: (open: boolean) => void
  colorizeConversation: (packetIndex: number, paletteIndex: number) => void
  resetTemporaryConversationColors: () => void
  setColorSlots: (original: Uint16Array, anonymized: Uint16Array, revision: number) => void
  persistUiPrefs: () => void
  setScrollTop: (top: number) => void
  setPaneScrollTop: (pane: PcapFocusedPane, top: number) => void
  setScrollAnchor: (packetIndex: number | null, leader: PcapFocusedPane | null) => void
  setRevealFilteredCounterpart: (reveal: boolean) => void
  setLiveAnnounce: (message: string) => void
  setActivePcapLevel: (level: PcapAnonymizationLevel) => void
  setRequestedPcapLevel: (level: PcapAnonymizationLevel | null) => void
  setActivePolicy: (policy: SanitizationPolicy) => void
  /** @deprecated */
  setActiveProfile: (profile: DerivedPcapPolicyView) => void
  /** @deprecated */
  setActiveProfileId: (id: string) => void
  /** @deprecated */
  setProfileDirty: (dirty: boolean) => void
  bumpProfileEpoch: () => void
  setReplaceDialog: (dialog: PcapReplaceDialog) => void
  setPendingReplaceFileName: (name: string | null) => void
  setPlanGeneration: (generation: number) => void
  setActivePlanGeneration: (generation: number) => void
  setPlanStale: (stale: boolean) => void
  setEntityCategoryFilter: (cat: string) => void
  setEntityQuery: (q: string) => void
  setHelpTopic: (topic: string | null) => void
  setExportHint: (hint: string | null) => void
  setExportBusy: (busy: boolean) => void
  setExportPhase: (phase: PcapExportPhase) => void
  setExportMessage: (message: string | null) => void
  setExportProgress: (done: number, total: number) => void
  setExportStartedAt: (startedAt: number) => void
  resetToEmpty: () => void
}

const MAX_FILTER_HISTORY = 20
const defaultLevel = DEFAULT_PCAP_LEVEL
const defaultProfile = derivedPolicyView(defaultLevel)
const defaultPolicy = presetToSanitizationPolicy(defaultLevel)
const initialUiPrefs = loadPcapUiPrefs()

function persistFromState(state: Pick<PcapUiState, 'dataView' | 'detailBytesLayout' | 'listPanelRatio' | 'detailsPanelRatio' | 'compareRatio' | 'panelSizesLinked' | 'columns' | 'colorizePacketList' | 'coloringRules'> & { userColoringRules?: readonly PcapColoringRule[] }): void {
  const userRules = state.userColoringRules ?? state.coloringRules.filter((r) => r.source === 'user')
  savePcapUiPrefs({
    dataView: state.dataView,
    detailBytesLayout: state.detailBytesLayout,
    listPanelRatio: state.listPanelRatio,
    detailsPanelRatio: state.detailsPanelRatio,
    compareRatio: state.compareRatio,
    panelSizesLinked: state.panelSizesLinked,
    columns: state.columns,
    colorizePacketList: state.colorizePacketList,
    userColoringRules: userRules,
  })
}

function initialColoringRules(): readonly PcapColoringRule[] {
  return mergeColoringRules(initialUiPrefs.userColoringRules, [])
}

export const usePcapStore = create<PcapUiState>((set, get) => ({
  phase: 'empty',
  sessionEpoch: 0,
  progress: createIdlePcapProgress(),
  errorMessage: null,
  selectedPacketIndex: -1,
  filter: { ...DEFAULT_PCAP_FILTER },
  displayFilterDraft: '',
  displayFilterApplied: '',
  displayFilterStatus: 'empty',
  displayFilterError: null,
  displayFilterHistory: [],
  filteredIndices: [],
  filteredIndicesOriginal: [],
  filteredIndicesAnonymized: [],
  selectedFieldPath: null,
  selectedByteOffset: null,
  activeByteSourceId: 'frame',
  expandedTreeNodes: [],
  markedPackets: [],
  selectionHistory: [],
  selectionHistoryIndex: -1,
  detailTab: 'tree',
  inspectorTab: 'overview',
  inspectorOpen: false,
  layoutMode: 'desktop',
  narrowPanel: 'list',
  compareLayout: 'dual',
  focusedPane: 'anonymized',
  compareRatio: initialUiPrefs.compareRatio,
  panelSizesLinked: initialUiPrefs.panelSizesLinked,
  workspaceWidth: 1600,
  dataView: initialUiPrefs.dataView,
  detailBytesLayout: initialUiPrefs.detailBytesLayout,
  listPanelRatio: initialUiPrefs.listPanelRatio,
  detailsPanelRatio: initialUiPrefs.detailsPanelRatio,
  columns: initialUiPrefs.columns,
  colorizePacketList: initialUiPrefs.colorizePacketList,
  coloringRules: initialColoringRules(),
  coloringRulesRevision: 1,
  temporaryConversationSlots: [],
  colorSlotsOriginal: new Uint16Array(0),
  colorSlotsAnonymized: new Uint16Array(0),
  colorSlotsRevision: 0,
  coloringRulesDialogOpen: false,
  recoverySearchDialogOpen: false,
  outcomeDialogOpen: false,
  scrollTop: 0,
  scrollTopOriginal: 0,
  scrollTopAnonymized: 0,
  revealFilteredCounterpart: false,
  liveAnnounce: '',
  scrollAnchorPacketIndex: null,
  scrollAnchorLeader: null,
  activePcapLevel: defaultLevel,
  requestedPcapLevel: null,
  activePolicy: defaultPolicy,
  activeProfile: defaultProfile,
  activeProfileId: defaultProfile.id,
  profileDirty: false,
  profileEpoch: 0,
  replaceDialog: 'none',
  pendingReplaceFileName: null,
  planGeneration: 0,
  activePlanGeneration: 0,
  planStale: false,
  entityCategoryFilter: 'all',
  entityQuery: '',
  helpTopic: null,
  exportHint: null,
  exportBusy: false,
  exportPhase: 'idle',
  exportMessage: null,
  exportPacketsDone: 0,
  exportPacketsTotal: 0,
  exportStartedAt: 0,
  setPhase: (phase) => set({ phase }),
  bumpSessionEpoch: () => set({ sessionEpoch: get().sessionEpoch + 1 }),
  setProgress: (progress) => set({ progress }),
  patchProgress: (patch) => set({ progress: { ...get().progress, ...patch } }),
  setErrorMessage: (errorMessage) => set({ errorMessage }),
  setSelectedPacketIndex: (selectedPacketIndex) => {
    const prev = get().selectedPacketIndex
    if (prev === selectedPacketIndex) return
    set({
      selectedPacketIndex,
      selectedFieldPath: null,
      selectedByteOffset: null,
      expandedTreeNodes: [],
    })
  },
  setFilter: (partial) => set({ filter: { ...get().filter, ...partial } }),
  setDisplayFilterDraft: (displayFilterDraft, displayFilterStatus, displayFilterError) =>
    set({ displayFilterDraft, displayFilterStatus, displayFilterError }),
  applyDisplayFilter: (expression) => {
    const trimmed = expression.trim()
    const history = trimmed.length > 0
      ? [trimmed, ...get().displayFilterHistory.filter((h) => h !== trimmed)].slice(0, MAX_FILTER_HISTORY)
      : get().displayFilterHistory
    set({
      displayFilterApplied: trimmed,
      displayFilterDraft: trimmed,
      displayFilterHistory: history,
      displayFilterStatus: trimmed.length === 0 ? 'empty' : get().displayFilterStatus,
      displayFilterError: trimmed.length === 0 ? null : get().displayFilterError,
    })
  },
  clearDisplayFilter: () =>
    set({
      displayFilterDraft: '',
      displayFilterApplied: '',
      displayFilterStatus: 'empty',
      displayFilterError: null,
    }),
  revertDisplayFilterDraft: () =>
    set({
      displayFilterDraft: get().displayFilterApplied,
      displayFilterStatus: get().displayFilterApplied.length === 0 ? 'empty' : 'valid',
      displayFilterError: null,
    }),
  setSelectedFieldPath: (selectedFieldPath) => set({ selectedFieldPath }),
  setSelectedByteOffset: (selectedByteOffset) => set({ selectedByteOffset }),
  setActiveByteSourceId: (activeByteSourceId) => set({ activeByteSourceId }),
  toggleTreeNode: (nodeId) => {
    const expanded = get().expandedTreeNodes
    set({
      expandedTreeNodes: expanded.includes(nodeId)
        ? expanded.filter((id) => id !== nodeId)
        : [...expanded, nodeId],
    })
  },
  setExpandedTreeNodes: (expandedTreeNodes) => set({ expandedTreeNodes }),
  expandAllTreeNodes: (nodeIds) => set({ expandedTreeNodes: [...nodeIds] }),
  collapseAllTreeNodes: () => set({ expandedTreeNodes: [] }),
  toggleMarkedPacket: (packetIndex) => {
    const marked = get().markedPackets
    set({
      markedPackets: marked.includes(packetIndex)
        ? marked.filter((i) => i !== packetIndex)
        : [...marked, packetIndex],
    })
  },
  pushSelectionSnapshot: (snapshot) => {
    const { history, index } = pushSelectionHistory(
      get().selectionHistory,
      get().selectionHistoryIndex,
      snapshot,
    )
    set({ selectionHistory: history, selectionHistoryIndex: index })
  },
  navigateSelectionHistory: (direction) => {
    const { snapshot, index } = navHistory(get().selectionHistory, get().selectionHistoryIndex, direction)
    if (!snapshot) return
    set({
      selectionHistoryIndex: index,
      selectedPacketIndex: snapshot.packetIndex,
      selectedFieldPath: snapshot.fieldPath,
      selectedByteOffset: snapshot.byteOffset,
    })
  },
  setDetailTab: (detailTab) => set({ detailTab }),
  setInspectorTab: (inspectorTab) => set({ inspectorTab }),
  setInspectorOpen: (inspectorOpen) => set({ inspectorOpen }),
  setLayoutMode: (layoutMode) => set({ layoutMode }),
  setNarrowPanel: (narrowPanel) => set({ narrowPanel }),
  setCompareLayout: (compareLayout) => {
    if (get().compareLayout === compareLayout) return
    set({ compareLayout })
  },
  setFocusedPane: (focusedPane) => {
    const indices =
      focusedPane === 'original' ? get().filteredIndicesOriginal : get().filteredIndicesAnonymized
    set({
      focusedPane,
      filteredIndices: indices,
      dataView: get().compareLayout === 'single' ? focusedPane : get().dataView,
    })
    if (get().compareLayout === 'single') {
      persistFromState({ ...get(), dataView: focusedPane })
    }
  },
  setCompareRatio: (ratio, opts) => {
    const compareRatio = clampCompareRatio(ratio)
    set({ compareRatio })
    if (opts?.persist !== false) persistFromState({ ...get(), compareRatio })
  },
  setPanelSizesLinked: (panelSizesLinked) => {
    set({ panelSizesLinked })
    persistFromState({ ...get(), panelSizesLinked })
  },
  setWorkspaceWidth: (workspaceWidth) => {
    if (Math.abs(get().workspaceWidth - workspaceWidth) < 0.5) return
    set({ workspaceWidth })
  },
  setDataView: (dataView) => {
    const indices =
      dataView === 'original' ? get().filteredIndicesOriginal : get().filteredIndicesAnonymized
    set({ dataView, focusedPane: dataView, filteredIndices: indices })
    persistFromState({ ...get(), dataView })
  },
  setDetailBytesLayout: (detailBytesLayout) => {
    set({ detailBytesLayout })
    persistFromState({ ...get(), detailBytesLayout })
  },
  setListPanelRatio: (listPanelRatio) => {
    set({ listPanelRatio })
    persistFromState({ ...get(), listPanelRatio })
  },
  setDetailsPanelRatio: (detailsPanelRatio) => {
    set({ detailsPanelRatio })
    persistFromState({ ...get(), detailsPanelRatio })
  },
  setColumns: (columns) => {
    set({ columns })
    persistFromState({ ...get(), columns })
  },
  resetColumns: () => {
    const columns = resetPcapColumnPrefs()
    set({ columns })
    persistFromState({ ...get(), columns })
  },
  setColorizePacketList: (colorizePacketList) => {
    set({ colorizePacketList })
    persistFromState({ ...get(), colorizePacketList })
  },
  setColoringRules: (userRules) => {
    const persistent = userRules.filter((r) => r.source === 'user')
    const coloringRules = mergeColoringRules(persistent, get().temporaryConversationSlots.map((t) => t.rule))
    set({ coloringRules, coloringRulesRevision: nextColoringRulesRevision() })
    persistFromState({ ...get(), coloringRules, userColoringRules: persistent })
  },
  resetColoringRulesToDefaults: () => {
    const coloringRules = mergeColoringRules([], get().temporaryConversationSlots.map((t) => t.rule))
    set({ coloringRules, coloringRulesRevision: nextColoringRulesRevision() })
    persistFromState({ ...get(), coloringRules, userColoringRules: [] })
  },
  setColoringRulesDialogOpen: (coloringRulesDialogOpen) => set({ coloringRulesDialogOpen }),
  setRecoverySearchDialogOpen: (recoverySearchDialogOpen) => set({ recoverySearchDialogOpen }),
  setOutcomeDialogOpen: (outcomeDialogOpen) => set({ outcomeDialogOpen }),
  colorizeConversation: (packetIndex, paletteIndex) => {
    const ctx = buildFilterContextFromSession(packetIndex, get().focusedPane)
    if (!ctx) return
    const conversationId = conversationIdFromFilterContext(ctx)
    if (!conversationId) return
    const idx = Math.max(0, Math.min(CONVERSATION_PALETTE.length - 1, paletteIndex))
    const palette = CONVERSATION_PALETTE[idx]!
    const filter = ctx.l4Proto === 'tcp'
      ? `tcp.port == ${ctx.srcPort} or tcp.port == ${ctx.dstPort}`
      : ctx.l4Proto === 'udp'
        ? `udp.port == ${ctx.srcPort} or udp.port == ${ctx.dstPort}`
        : ctx.srcIpv4
          ? `ip.addr == ${ctx.srcIpv4} or ip.addr == ${ctx.dstIpv4}`
          : `eth.addr == ${ctx.srcMac}`
    const rule: PcapColoringRule = {
      id: `temp-conv-${conversationId}`,
      name: `Conversation ${idx + 1}`,
      enabled: true,
      priority: 5 + idx,
      filter,
      light: palette.light,
      dark: palette.dark,
      source: 'temporary-conversation',
    }
    const slots = get().temporaryConversationSlots.filter((t) => t.conversationId !== conversationId)
    const nextSlots = [...slots, { conversationId, paletteIndex: idx, rule }]
    const coloringRules = mergeColoringRules(
      get().coloringRules.filter((r) => r.source === 'user'),
      nextSlots.map((t) => t.rule),
    )
    set({
      temporaryConversationSlots: nextSlots,
      coloringRules,
      coloringRulesRevision: nextColoringRulesRevision(),
    })
  },
  resetTemporaryConversationColors: () => {
    const coloringRules = mergeColoringRules(
      get().coloringRules.filter((r) => r.source === 'user'),
      [],
    )
    set({
      temporaryConversationSlots: [],
      coloringRules,
      coloringRulesRevision: nextColoringRulesRevision(),
    })
  },
  setColorSlots: (colorSlotsOriginal, colorSlotsAnonymized, colorSlotsRevision) =>
    set({ colorSlotsOriginal, colorSlotsAnonymized, colorSlotsRevision }),
  persistUiPrefs: () => persistFromState(get()),
  setScrollTop: (scrollTop) => set({ scrollTop }),
  setPaneScrollTop: (pane, top) => {
    if (pane === 'original') set({ scrollTopOriginal: top, scrollTop: get().dataView === 'original' ? top : get().scrollTop })
    else set({ scrollTopAnonymized: top, scrollTop: get().dataView === 'anonymized' ? top : get().scrollTop })
  },
  setScrollAnchor: (scrollAnchorPacketIndex, scrollAnchorLeader) =>
    set({ scrollAnchorPacketIndex, scrollAnchorLeader }),
  setFilteredIndices: (filteredIndices) => set({ filteredIndices }),
  setFilteredIndicesForViews: (filteredIndicesOriginal, filteredIndicesAnonymized) => {
    const dataView = get().dataView
    set({
      filteredIndicesOriginal,
      filteredIndicesAnonymized,
      filteredIndices: dataView === 'original' ? filteredIndicesOriginal : filteredIndicesAnonymized,
    })
  },
  setRevealFilteredCounterpart: (revealFilteredCounterpart) => set({ revealFilteredCounterpart }),
  setLiveAnnounce: (liveAnnounce) => set({ liveAnnounce }),
  setActivePcapLevel: (activePcapLevel) =>
    set({
      activePcapLevel,
      activeProfile: derivedPolicyView(activePcapLevel),
      activeProfileId: `pcap-${activePcapLevel}`,
      activePolicy: presetToSanitizationPolicy(activePcapLevel),
    }),
  setRequestedPcapLevel: (requestedPcapLevel) => set({ requestedPcapLevel }),
  setActivePolicy: (activePolicy) => set({ activePolicy }),
  setActiveProfile: (activeProfile) =>
    set({
      activeProfile,
      activePcapLevel: activeProfile.preset,
      activeProfileId: activeProfile.id,
      activePolicy: presetToSanitizationPolicy(activeProfile.preset),
    }),
  setActiveProfileId: (activeProfileId) => set({ activeProfileId }),
  setProfileDirty: () => set({ profileDirty: false }),
  bumpProfileEpoch: () => set({ profileEpoch: get().profileEpoch + 1 }),
  setReplaceDialog: (replaceDialog) => set({ replaceDialog }),
  setPendingReplaceFileName: (pendingReplaceFileName) => set({ pendingReplaceFileName }),
  setPlanGeneration: (planGeneration) => set({ planGeneration }),
  setActivePlanGeneration: (activePlanGeneration) =>
    set({ activePlanGeneration, planStale: get().planGeneration !== activePlanGeneration }),
  setPlanStale: (planStale) => set({ planStale }),
  setEntityCategoryFilter: (entityCategoryFilter) => set({ entityCategoryFilter }),
  setEntityQuery: (entityQuery) => set({ entityQuery }),
  setHelpTopic: (helpTopic) => set({ helpTopic }),
  setExportHint: (exportHint) => set({ exportHint }),
  setExportBusy: (exportBusy) => set({ exportBusy }),
  setExportPhase: (exportPhase) => set({ exportPhase }),
  setExportMessage: (exportMessage) => set({ exportMessage }),
  setExportProgress: (exportPacketsDone, exportPacketsTotal) => set({ exportPacketsDone, exportPacketsTotal }),
  setExportStartedAt: (exportStartedAt) => set({ exportStartedAt }),
  resetToEmpty: () =>
    set({
      phase: 'empty',
      progress: createIdlePcapProgress(),
      errorMessage: null,
      selectedPacketIndex: -1,
      filter: { ...DEFAULT_PCAP_FILTER },
      displayFilterDraft: '',
      displayFilterApplied: '',
      displayFilterStatus: 'empty',
      displayFilterError: null,
      filteredIndices: [],
      filteredIndicesOriginal: [],
      filteredIndicesAnonymized: [],
      selectedFieldPath: null,
      selectedByteOffset: null,
      expandedTreeNodes: [],
      markedPackets: [],
      selectionHistory: [],
      selectionHistoryIndex: -1,
      detailTab: 'tree',
      scrollTop: 0,
      scrollTopOriginal: 0,
      scrollTopAnonymized: 0,
      temporaryConversationSlots: [],
      colorSlotsOriginal: new Uint16Array(0),
      colorSlotsAnonymized: new Uint16Array(0),
      revealFilteredCounterpart: false,
      liveAnnounce: '',
      focusedPane: 'anonymized',
      outcomeDialogOpen: false,
      coloringRulesDialogOpen: false,
      recoverySearchDialogOpen: false,
      exportHint: null,
      exportBusy: false,
      exportPhase: 'idle',
      exportMessage: null,
      exportPacketsDone: 0,
      exportPacketsTotal: 0,
      exportStartedAt: 0,
      requestedPcapLevel: null,
      planStale: false,
    }),
}))

export type { PcapUiPrefs }
