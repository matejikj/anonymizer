import { create } from 'zustand'
import type { ImportProgress } from '../features/import-log/importProgress.ts'
import { createIdleProgress } from '../features/import-log/importProgress.ts'
import type { WorkerClientStatus } from './workerClient.ts'
import {
  DEFAULT_SPLITTER_RATIO,
  loadPreference,
  savePreference,
} from '../persistence/preferencesRepository.ts'
import {
  applyThemePreference,
  loadThemePreference,
  saveThemePreference,
  type ThemePreference,
} from './theme.ts'
import type { ResourceConflict } from '../pcap/ui/pcapResourceCoordinator.ts'
import { BUILTIN_UNIFIED_PROFILE_ID } from '../domain/configSchema.ts'
import type { TextEncodingLabel, EncodingConfidence } from '../features/import-log/textEncoding.ts'
import type { StructuredLogFormat } from '../engine/structuredLogSanitize.ts'

export type AppPhase =
  | 'empty'
  | 'importing'
  | 'workspace'
  | 'resolve-only'
  | 'correlation-staging'
  | 'correlation-processing'
  | 'correlation-review'
  | 'correlation-exporting'
  | 'correlation-completed'
export type AppMode = 'text' | 'pcap'

export interface AppShellState {
  activeMode: AppMode
  phase: AppPhase
  statusMessage: string
  lastError: string | null
  generation: string
  workerStatus: WorkerClientStatus
  importProgress: ImportProgress
  wrapEnabled: boolean
  splitterRatio: number
  focusedLine: number
  /** Index into packed match array for occurrence navigation; -1 = none. */
  occurrenceIndex: number
  /**
   * Bumped when session model is created/cleared so React Compiler re-reads
   * module-scoped session state during render.
   */
  sessionEpoch: number
  /** Bumped when resolve-only imported bundle changes. */
  resolveOnlyEpoch: number
  /** Bumped when correlation session model changes (Stage 23). */
  correlationEpoch: number
  correlationPhase: 'empty' | 'staged' | 'processing' | 'ready' | 'failed'
  correlationSourceCount: number
  correlationMappingRevision: number | null
  selectedCorrelationSourceId: 'all' | string
  /** Session resolve lookup panel (Stage 22). */
  resolvePanelOpen: boolean
  reviewTab: 'overview' | 'entities' | 'rules' | 'shared'
  entityFilter: 'all' | import('../domain/types.ts').Category
  entityQuery: string
  planBusy: boolean
  toast: { message: string; undoLabel?: string; kind?: string } | null
  ruleFormOpen: boolean
  editingRuleId: string | null
  profileDirty: boolean
  profileEpoch: number
  activeProfileId: string
  profileDialog:
    | 'none'
    | 'edit'
    | 'import'
    | 'export-warn'
    | 'clear-data'
    | 'switch-dirty'
    | 'mode-switch-dirty'
  pendingSwitchProfileId: string | null
  pendingSwitchMode: AppMode | null
  helpOpen: boolean
  docsOpen: boolean
  textOutcomeDialogOpen: boolean
  themePreference: ThemePreference
  resourceConflict: ResourceConflict | null
  /** T43 — last text import encoding / structured format (report metadata). */
  textSourceMeta: {
    sourceEncoding: TextEncodingLabel
    outputEncoding: 'utf-8'
    encodingConfidence: EncodingConfidence
    structuredFormat?: StructuredLogFormat
  } | null
  /** T43 — optional encoding override for next text file import (null = auto-detect). */
  textEncodingOverride: TextEncodingLabel | null
  setActiveMode: (mode: AppMode) => void
  setPhase: (phase: AppPhase) => void
  setStatusMessage: (message: string) => void
  setLastError: (message: string | null) => void
  setGeneration: (generation: string) => void
  setWorkerStatus: (status: WorkerClientStatus) => void
  setImportProgress: (progress: ImportProgress) => void
  patchImportProgress: (patch: Partial<ImportProgress>) => void
  setWrapEnabled: (wrap: boolean) => void
  setSplitterRatio: (ratio: number) => void
  setFocusedLine: (line: number) => void
  setOccurrenceIndex: (index: number) => void
  bumpSessionEpoch: () => void
  setReviewTab: (tab: AppShellState['reviewTab']) => void
  setEntityFilter: (filter: AppShellState['entityFilter']) => void
  setEntityQuery: (query: string) => void
  setPlanBusy: (busy: boolean) => void
  setToast: (toast: AppShellState['toast']) => void
  setRuleFormOpen: (open: boolean) => void
  setEditingRuleId: (id: string | null) => void
  setProfileDirty: (dirty: boolean) => void
  bumpProfileEpoch: () => void
  setActiveProfileId: (id: string) => void
  setProfileDialog: (dialog: AppShellState['profileDialog']) => void
  setPendingSwitchProfileId: (id: string | null) => void
  setPendingSwitchMode: (mode: AppMode | null) => void
  setHelpOpen: (open: boolean) => void
  setDocsOpen: (open: boolean) => void
  setTextOutcomeDialogOpen: (open: boolean) => void
  setThemePreference: (pref: ThemePreference) => void
  setResourceConflict: (conflict: ResourceConflict | null) => void
  setTextSourceMeta: (meta: AppShellState['textSourceMeta']) => void
  setTextEncodingOverride: (encoding: TextEncodingLabel | null) => void
  enterResolveOnly: () => void
  exitResolveOnly: () => void
  setResolvePanelOpen: (open: boolean) => void
  bumpCorrelationEpoch: () => void
  setCorrelationView: (view: {
    phase: AppShellState['correlationPhase']
    sourceCount: number
    mappingRevision: number | null
  }) => void
  setSelectedCorrelationSourceId: (sourceId: 'all' | string) => void
  resetSession: () => void
}

/**
 * Shell + UI preference store.
 * Large log strings / packed matches must never live here (ARCHITECTURE §5.2 / §9.1).
 */
export const useAppStore = create<AppShellState>((set) => ({
  activeMode: loadPreference('activeMode', 'text') as AppMode,
  phase: 'empty',
  statusMessage: '',
  lastError: null,
  generation: '',
  workerStatus: 'idle',
  importProgress: createIdleProgress(),
  wrapEnabled: loadPreference('wrap', false),
  splitterRatio: loadPreference('splitterRatio', DEFAULT_SPLITTER_RATIO),
  focusedLine: 1,
  occurrenceIndex: -1,
  sessionEpoch: 0,
  resolveOnlyEpoch: 0,
  correlationEpoch: 0,
  correlationPhase: 'empty',
  correlationSourceCount: 0,
  correlationMappingRevision: null,
  selectedCorrelationSourceId: 'all',
  resolvePanelOpen: false,
  reviewTab: 'overview',
  entityFilter: 'all',
  entityQuery: '',
  planBusy: false,
  toast: null,
  ruleFormOpen: false,
  editingRuleId: null,
  profileDirty: false,
  profileEpoch: 0,
  activeProfileId: BUILTIN_UNIFIED_PROFILE_ID,
  profileDialog: 'none',
  pendingSwitchProfileId: null,
  pendingSwitchMode: null,
  helpOpen: false,
  docsOpen: false,
  textOutcomeDialogOpen: false,
  themePreference: loadThemePreference(),
  resourceConflict: null,
  textSourceMeta: null,
  textEncodingOverride: null,
  setActiveMode: (activeMode) => {
    savePreference('activeMode', activeMode)
    set({ activeMode })
  },
  setPhase: (phase) => set({ phase }),
  setStatusMessage: (statusMessage) => set({ statusMessage }),
  setLastError: (lastError) => set({ lastError }),
  setGeneration: (generation) => set({ generation }),
  setWorkerStatus: (workerStatus) => set({ workerStatus }),
  setImportProgress: (importProgress) => set({ importProgress }),
  patchImportProgress: (patch) =>
    set((s) => ({ importProgress: { ...s.importProgress, ...patch } })),
  setWrapEnabled: (wrapEnabled) => {
    savePreference('wrap', wrapEnabled)
    set({ wrapEnabled })
  },
  setSplitterRatio: (splitterRatio) => set({ splitterRatio }),
  setFocusedLine: (focusedLine) => set({ focusedLine }),
  setOccurrenceIndex: (occurrenceIndex) => set({ occurrenceIndex }),
  bumpSessionEpoch: () => set((s) => ({ sessionEpoch: s.sessionEpoch + 1 })),
  setReviewTab: (reviewTab) => set({ reviewTab }),
  setEntityFilter: (entityFilter) => set({ entityFilter }),
  setEntityQuery: (entityQuery) => set({ entityQuery }),
  setPlanBusy: (planBusy) => set({ planBusy }),
  setToast: (toast) => set({ toast }),
  setRuleFormOpen: (ruleFormOpen) => set({ ruleFormOpen }),
  setEditingRuleId: (editingRuleId) => set({ editingRuleId }),
  setProfileDirty: (profileDirty) => set({ profileDirty }),
  bumpProfileEpoch: () => set((s) => ({ profileEpoch: s.profileEpoch + 1 })),
  setActiveProfileId: (activeProfileId) => set({ activeProfileId }),
  setProfileDialog: (profileDialog) => set({ profileDialog }),
  setPendingSwitchProfileId: (pendingSwitchProfileId) => set({ pendingSwitchProfileId }),
  setPendingSwitchMode: (pendingSwitchMode) => set({ pendingSwitchMode }),
  setHelpOpen: (helpOpen) => set({ helpOpen }),
  setDocsOpen: (docsOpen) => set({ docsOpen }),
  setTextOutcomeDialogOpen: (textOutcomeDialogOpen) => set({ textOutcomeDialogOpen }),
  setThemePreference: (themePreference) => {
    saveThemePreference(themePreference)
    applyThemePreference(themePreference)
    set({ themePreference })
  },
  setResourceConflict: (resourceConflict) => set({ resourceConflict }),
  setTextSourceMeta: (textSourceMeta) => set({ textSourceMeta }),
  setTextEncodingOverride: (textEncodingOverride) => set({ textEncodingOverride }),
  enterResolveOnly: () =>
    set((s) => ({
      phase: 'resolve-only',
      resolveOnlyEpoch: s.resolveOnlyEpoch + 1,
      statusMessage: '',
    })),
  exitResolveOnly: () =>
    set((s) => ({
      phase: 'empty',
      resolveOnlyEpoch: s.resolveOnlyEpoch + 1,
      resolvePanelOpen: false,
    })),
  setResolvePanelOpen: (resolvePanelOpen) => set({ resolvePanelOpen }),
  bumpCorrelationEpoch: () => set((s) => ({ correlationEpoch: s.correlationEpoch + 1 })),
  setCorrelationView: ({ phase, sourceCount, mappingRevision }) =>
    set({ correlationPhase: phase, correlationSourceCount: sourceCount, correlationMappingRevision: mappingRevision }),
  setSelectedCorrelationSourceId: (selectedCorrelationSourceId) => set({ selectedCorrelationSourceId }),
  resetSession: () =>
    set({
      phase: 'empty',
      statusMessage: '',
      lastError: null,
      generation: '',
      workerStatus: 'idle',
      importProgress: createIdleProgress(),
      textSourceMeta: null,
      focusedLine: 1,
      occurrenceIndex: -1,
      sessionEpoch: 0,
      resolveOnlyEpoch: 0,
      correlationEpoch: 0,
      correlationPhase: 'empty',
      correlationSourceCount: 0,
      correlationMappingRevision: null,
      selectedCorrelationSourceId: 'all',
      resolvePanelOpen: false,
      reviewTab: 'overview',
      entityFilter: 'all',
      entityQuery: '',
      planBusy: false,
      toast: null,
      ruleFormOpen: false,
      editingRuleId: null,
      profileDialog: 'none',
      pendingSwitchProfileId: null,
      pendingSwitchMode: null,
      helpOpen: false,
      docsOpen: false,
      textOutcomeDialogOpen: false,
      resourceConflict: null,
      // keep wrap + splitter + theme + profileDirty / active profile across log sessions
    }),
}))
