/**
 * Per-source UI context for mixed-set review — survives source switches.
 * In-memory only (never browser storage).
 */

import type { Category } from '../domain/types'
import type { PcapDataView, PcapDetailBytesLayout } from '../pcap/ui/pcapUiPrefs'
import type { PcapCompareLayout } from '../pcap/ui/pcapCompareLayout'
import type { PcapInspectorTab, PcapDetailTab } from '../pcap/ui/pcapStore'
import type { PcapFilterState } from '../pcap/ui/pcapSession'
import { DEFAULT_PCAP_FILTER } from '../pcap/ui/pcapSession'

export interface TextSourceUiContext {
  readonly originalQuery: string
  readonly originalCase: boolean
  readonly anonQuery: string
  readonly anonCase: boolean
  readonly occurrenceIndex: number
  readonly focusedLine: number
  readonly reviewTab: 'overview' | 'entities' | 'rules' | 'shared'
  readonly entityFilter: 'all' | Category
  readonly entityQuery: string
  readonly wrapEnabled: boolean
}

export interface PcapSourceUiContext {
  readonly displayFilterDraft: string
  readonly displayFilterApplied: string
  readonly selectedPacketIndex: number
  readonly selectedFieldPath: string | null
  readonly selectedByteOffset: number | null
  readonly inspectorOpen: boolean
  readonly inspectorTab: PcapInspectorTab
  readonly detailTab: PcapDetailTab
  readonly dataView: PcapDataView
  readonly compareLayout: PcapCompareLayout
  readonly detailBytesLayout: PcapDetailBytesLayout
  readonly filter: PcapFilterState
}

const textBySource = new Map<string, TextSourceUiContext>()
const pcapBySource = new Map<string, PcapSourceUiContext>()

/** Mount token: sourceId + generation; rejects stale async materialization. */
let activeMountToken: string | null = null

export function makeSourceMountToken(sourceId: string, generationId: string): string {
  return `${sourceId}::${generationId}`
}

export function beginSourceMount(token: string): void {
  activeMountToken = token
}

export function isSourceMountCurrent(token: string): boolean {
  return activeMountToken === token
}

export function clearSourceMountToken(): void {
  activeMountToken = null
}

export function rememberTextSourceUi(sourceId: string, state: TextSourceUiContext): void {
  textBySource.set(sourceId, state)
}

export function getTextSourceUi(sourceId: string): TextSourceUiContext | undefined {
  return textBySource.get(sourceId)
}

export function rememberPcapSourceUi(sourceId: string, state: PcapSourceUiContext): void {
  pcapBySource.set(sourceId, state)
}

export function getPcapSourceUi(sourceId: string): PcapSourceUiContext | undefined {
  return pcapBySource.get(sourceId)
}

export function resetCorrelationSourceUiContext(): void {
  textBySource.clear()
  pcapBySource.clear()
  activeMountToken = null
}

export function defaultTextSourceUi(partial?: Partial<TextSourceUiContext>): TextSourceUiContext {
  return {
    originalQuery: '',
    originalCase: false,
    anonQuery: '',
    anonCase: false,
    occurrenceIndex: -1,
    focusedLine: 1,
    reviewTab: 'overview',
    entityFilter: 'all',
    entityQuery: '',
    wrapEnabled: false,
    ...partial,
  }
}

export function defaultPcapSourceUi(partial?: Partial<PcapSourceUiContext>): PcapSourceUiContext {
  return {
    displayFilterDraft: '',
    displayFilterApplied: '',
    selectedPacketIndex: -1,
    selectedFieldPath: null,
    selectedByteOffset: null,
    inspectorOpen: true,
    inspectorTab: 'overview',
    detailTab: 'changes',
    dataView: 'anonymized',
    compareLayout: 'dual',
    detailBytesLayout: 'stacked',
    filter: { ...DEFAULT_PCAP_FILTER },
    ...partial,
  }
}
