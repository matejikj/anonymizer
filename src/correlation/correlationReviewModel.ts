/**
 * Correlation review workspace model (Stage 28).
 */

import type { IdentityCategory } from '../mapping/identityCategories'
import type { OccurrenceRef } from '../mapping/types'
import { getSharedMappingClient } from '../mapping/sharedMappingClient'
import {
  correlationRegistryKeyFromParts,
  crossFormatCategoryFromIdentity,
  lookupCrossFormatAlias,
} from '../mapping/crossFormat'
import type { CrossFormatCategory } from '../mapping/crossFormat/types'
import { SourceKind as SK } from '../domain/sourceArtifact'
import { useAppStore } from '../app/store'
import { listCorrelationSources } from './correlationSessionModel'
import type { CorrelationSourceRecord } from './types'
import { assessCorrelationSourceExport } from './export/correlationExportSecurity'
import { cs } from '../i18n/cs'
import { isExportBlockedBySessionPolicy } from './profileCompatibility/sessionPolicy'

export type CorrelationSelection = 'all' | string
export type EntityListMode = 'shared' | 'all'

export interface CorrelationEntityRow {
  readonly key: string
  readonly category: IdentityCategory
  readonly alias: string
  /** Human-readable sample from discovery (falls back to canonical). */
  readonly original: string
  readonly sourceIds: readonly string[]
  readonly occurrences: readonly OccurrenceRef[]
  readonly shared: boolean
  readonly maskedOriginal: string
}

export interface CorrelationWorkspaceSummary {
  readonly sourceCount: number
  readonly readyCount: number
  readonly reviewCount: number
  readonly nextProblemSourceId: string | null
  /** Human-readable reason for the next problem source, if any. */
  readonly nextProblemReason: string | null
}

export interface SourceScrollState {
  readonly line?: number
  readonly packetIndex?: number
}

let selectedSourceId: CorrelationSelection = 'all'
let entityListMode: EntityListMode = 'shared'
let revealOriginal = true
let flatOccurrenceCursor = -1
let flatOccurrenceList: OccurrenceRef[] = []
const scrollBySource = new Map<string, SourceScrollState>()

function bump(): void {
  useAppStore.getState().bumpCorrelationEpoch()
}

export function resetCorrelationReviewModel(): void {
  selectedSourceId = 'all'
  useAppStore.getState().setSelectedCorrelationSourceId('all')
  entityListMode = 'shared'
  revealOriginal = true
  flatOccurrenceCursor = -1
  flatOccurrenceList = []
  scrollBySource.clear()
}

export function getSelectedCorrelationSource(): CorrelationSelection {
  return selectedSourceId
}

export function selectCorrelationSource(sourceId: CorrelationSelection): void {
  selectedSourceId = sourceId
  useAppStore.getState().setSelectedCorrelationSourceId(sourceId)
  bump()
}

export function getEntityListMode(): EntityListMode {
  return entityListMode
}

export function setEntityListMode(mode: EntityListMode): void {
  entityListMode = mode
  bump()
}

export function isOriginalRevealed(): boolean {
  return revealOriginal
}

export function setOriginalRevealed(revealed: boolean): void {
  revealOriginal = revealed
  bump()
}

export function rememberSourceScroll(sourceId: string, state: SourceScrollState): void {
  scrollBySource.set(sourceId, state)
}

export function getSourceScroll(sourceId: string): SourceScrollState | undefined {
  return scrollBySource.get(sourceId)
}

function maskOriginal(value: string): string {
  if (value.length <= 4) return '••••'
  return `${value.slice(0, 2)}${'•'.repeat(Math.min(8, value.length - 4))}${value.slice(-2)}`
}

function aliasForIdentity(
  category: IdentityCategory,
  canonical: string,
  originalSpelling?: string,
): string {
  const snapshot = getSharedMappingClient().getPublishedSnapshot()
  if (!snapshot) return canonical
  const viaCf = lookupCrossFormatAlias(snapshot, category, canonical, undefined, originalSpelling)
  if (viaCf) return viaCf
  const entry = snapshot.entries.find((e) => e.category === category && e.canonical === canonical)
  return entry?.alias ?? canonical
}

function originalForIdentity(category: IdentityCategory, canonical: string): string {
  void category
  return canonical
}

export function buildCorrelationEntityRows(mode: EntityListMode = entityListMode): CorrelationEntityRow[] {
  const grouped = new Map<
    string,
    {
      category: IdentityCategory
      canonical: string
      originalSpelling?: string
      sourceIds: Set<string>
      occurrences: OccurrenceRef[]
    }
  >()

  for (const source of listCorrelationSources()) {
    if (!source.discovery || source.phase !== 'planned') continue
    for (const id of source.discovery.identities) {
      // T45 — group by cross-format registry key so sip:/tel: phone shares one row.
      const key = correlationRegistryKeyFromParts(
        id.category,
        id.canonical,
        id.constraint,
        id.originalSpelling,
      )
      let row = grouped.get(key)
      if (!row) {
        row = {
          category: id.category,
          canonical: id.canonical,
          originalSpelling: id.originalSpelling,
          sourceIds: new Set(),
          occurrences: [],
        }
        grouped.set(key, row)
      } else if (!row.originalSpelling && id.originalSpelling) {
        row.originalSpelling = id.originalSpelling
      }
      row.sourceIds.add(source.sourceId)
      if (id.occurrence) row.occurrences.push(id.occurrence)
    }
  }

  const rows: CorrelationEntityRow[] = []
  for (const [key, row] of grouped) {
    const sourceIds = [...row.sourceIds]
    const shared = sourceIds.length >= 2
    if (mode === 'shared' && !shared) continue
    const canonical = row.canonical
    const original = row.originalSpelling ?? originalForIdentity(row.category, canonical)
    rows.push({
      key,
      category: row.category,
      alias: aliasForIdentity(row.category, canonical, row.originalSpelling),
      original,
      sourceIds,
      occurrences: row.occurrences,
      shared,
      maskedOriginal: maskOriginal(original),
    })
  }

  rows.sort((a, b) => {
    if (b.occurrences.length !== a.occurrences.length) return b.occurrences.length - a.occurrences.length
    return a.alias.localeCompare(b.alias, 'cs')
  })
  return rows
}

/** T45 — counts of shared identities per cross-format category (no values). */
export function buildCrossFormatSharedCategoryCounts(): ReadonlyArray<{
  readonly category: CrossFormatCategory
  readonly count: number
}> {
  const counts = new Map<CrossFormatCategory, number>()
  for (const row of buildCorrelationEntityRows('shared')) {
    const cf = crossFormatCategoryFromIdentity(
      row.category,
      row.original,
    )
    if (!cf) continue
    counts.set(cf, (counts.get(cf) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => a.category.localeCompare(b.category))
}

export function buildFlatOccurrenceList(entityKey?: string): OccurrenceRef[] {
  const sourceOrder = listCorrelationSources().map((s) => s.sourceId)
  const rank = new Map(sourceOrder.map((id, i) => [id, i]))
  const rows = entityKey
    ? buildCorrelationEntityRows('all').filter((r) => r.key === entityKey)
    : buildCorrelationEntityRows(entityListMode)
  const all = rows.flatMap((r) => r.occurrences)
  all.sort((a, b) => {
    const ra = rank.get(a.sourceId) ?? 999
    const rb = rank.get(b.sourceId) ?? 999
    if (ra !== rb) return ra - rb
    if (a.kind === 'text' && b.kind === 'text') {
      if (a.line !== b.line) return a.line - b.line
      return a.start - b.start
    }
    if (a.kind === 'packet' && b.kind === 'packet') return a.packetIndex - b.packetIndex
    return 0
  })
  flatOccurrenceList = all
  return all
}

export function getFlatOccurrenceCursor(): number {
  return flatOccurrenceCursor
}

export function setFlatOccurrenceCursor(index: number): OccurrenceRef | null {
  if (flatOccurrenceList.length === 0) buildFlatOccurrenceList()
  if (flatOccurrenceList.length === 0) return null
  flatOccurrenceCursor = ((index % flatOccurrenceList.length) + flatOccurrenceList.length) % flatOccurrenceList.length
  bump()
  return flatOccurrenceList[flatOccurrenceCursor] ?? null
}

export function stepFlatOccurrence(delta: 1 | -1): OccurrenceRef | null {
  return setFlatOccurrenceCursor(flatOccurrenceCursor + delta)
}

export function getCorrelationWorkspaceSummary(): CorrelationWorkspaceSummary {
  const sources = listCorrelationSources()
  let readyCount = 0
  let reviewCount = 0
  let nextProblemSourceId: string | null = null
  let nextProblemReason: string | null = null

  for (const source of sources) {
    if (source.phase === 'planned' && source.exportState === 'ready') {
      readyCount += 1
      continue
    }
    reviewCount += 1
    if (!nextProblemSourceId && sourceNeedsReview(source)) {
      nextProblemSourceId = source.sourceId
      nextProblemReason = sourceProblemReason(source)
    }
  }

  return {
    sourceCount: sources.length,
    readyCount,
    reviewCount,
    nextProblemSourceId,
    nextProblemReason,
  }
}

function sourceNeedsReview(source: CorrelationSourceRecord): boolean {
  if (source.phase === 'failed') return true
  if (source.exportState === 'blocked') return true
  if (source.coverageState === 'partial') return true
  // Unplanned / still processing sources also need attention.
  if (source.phase !== 'planned') return true
  return false
}

/** Stable Czech reason for UI (step 1 problem navigation) — informational, never a call to action. */
export function sourceProblemReason(source: CorrelationSourceRecord): string {
  if (source.phase === 'failed') {
    return source.errorMessage?.trim() || 'Zpracování tohoto souboru selhalo.'
  }
  if (source.exportState === 'blocked') {
    return 'Export tohoto souboru je zablokovaný (ochranný zásah enginu).'
  }
  if (source.coverageState === 'partial') {
    return 'U části dat je obsah skrytý — AI ji neuvidí.'
  }
  if (source.phase !== 'planned') {
    return 'Soubor ještě nemá hotový plán anonymizace.'
  }
  return 'Soubor ještě není připravený k exportu.'
}

export function sourceStatusLabel(source: CorrelationSourceRecord): string {
  if (useAppStore.getState().planBusy || isExportBlockedBySessionPolicy()) {
    return cs.correlationWorkspace.statusRebuilding
  }
  if (source.phase === 'failed') return cs.correlationWorkspace.statusFailed
  if (source.exportState === 'blocked') return cs.correlationWorkspace.statusBlocked
  if (source.phase !== 'planned') return cs.correlationWorkspace.statusPending

  const security = assessCorrelationSourceExport({
    ...source,
    // assess early-returns blocked when exportState !== ready; force evaluate content
    exportState: 'ready',
  })
  if (security === 'blocked') return cs.correlationWorkspace.statusBlocked
  if (security === 'exposed' || source.coverageState === 'partial') {
    return cs.correlationWorkspace.statusExposed
  }
  if (
    source.discovery?.kind === 'text' &&
    source.discovery.detection.entities.length === 0
  ) {
    return cs.correlationWorkspace.statusNoFindings
  }
  if (source.exportState === 'ready') return cs.correlationWorkspace.statusReady
  return cs.correlationWorkspace.statusNeedsReview
}

/** First source that needs attention, otherwise the first file in the set. */
export function pickInitialCorrelationSourceId(): string | null {
  const sources = listCorrelationSources()
  if (sources.length === 0) return null
  const summary = getCorrelationWorkspaceSummary()
  if (summary.nextProblemSourceId) return summary.nextProblemSourceId
  return sources[0]!.sourceId
}

export function sourceKindShort(kind: typeof SK.Text | typeof SK.Pcap): string {
  if (kind === SK.Pcap) return 'PCAP'
  return 'LOG'
}

export function isMultiSourceCorrelationReview(): boolean {
  return listCorrelationSources().length > 1
}
