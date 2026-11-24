/**
 * Multi-source correlation processing progress (Stage 28).
 * Module-scoped — large session data stays out of Zustand.
 */

import { SourceKind as SK } from '../domain/sourceArtifact'
import { useAppStore } from '../app/store'
import { listCorrelationSources } from './correlationSessionModel'

export type SourceProgressStatus = 'waiting' | 'active' | 'done' | 'failed'

export interface CorrelationSourceProgressRow {
  readonly sourceId: string
  readonly fileName: string
  readonly kind: typeof SK.Text | typeof SK.Pcap
  readonly status: SourceProgressStatus
  readonly phaseLabel: string
  readonly done: number | null
  readonly total: number | null
  readonly valueCount: number | null
}

export interface CorrelationProgressState {
  readonly active: boolean
  readonly aggregatePercent: number
  readonly phaseLabel: string
  readonly liveAnnouncement: string | null
  readonly startedAt: number
  readonly sources: readonly CorrelationSourceProgressRow[]
}

const EMPTY: CorrelationProgressState = {
  active: false,
  aggregatePercent: 0,
  phaseLabel: '',
  liveAnnouncement: null,
  startedAt: 0,
  sources: [],
}

let state: CorrelationProgressState = EMPTY
let revision = 0

function bump(): void {
  revision += 1
  useAppStore.getState().bumpCorrelationEpoch()
}

export function getCorrelationProgressRevision(): number {
  return revision
}

export function getCorrelationProgressState(): CorrelationProgressState {
  return state
}

export function resetCorrelationProgress(): void {
  state = EMPTY
  revision = 0
}

function humanPhase(phase: string, done: number, total: number): string {
  if (phase === 'lines' || phase === 'decode') {
    return total > 0 ? `Analyzuji řádek ${done.toLocaleString('cs-CZ')} z ${total.toLocaleString('cs-CZ')}` : 'Analyzuji text…'
  }
  if (phase === 'packets' || phase === 'pcap') {
    return total > 0 ? `Analyzuji paket ${done.toLocaleString('cs-CZ')} z ${total.toLocaleString('cs-CZ')}` : 'Analyzuji capture…'
  }
  if (phase === 'coverage') return 'Kontroluji pokrytí…'
  if (phase === 'resolve' || phase === 'mapping') {
    return total > 0 ? `Sjednocuji společné hodnoty… (${done}/${total})` : 'Sjednocuji společné hodnoty…'
  }
  if (phase === 'plan') {
    return total > 0 ? `Připravuji náhled… (${done}/${total})` : 'Připravuji náhled…'
  }
  if (phase === 'preparing') return 'Připravuji společnou relaci…'
  return 'Analyzuji…'
}

function computeAggregate(sources: readonly CorrelationSourceProgressRow[]): number {
  if (sources.length === 0) return 0
  let sum = 0
  for (const row of sources) {
    if (row.status === 'done') {
      sum += 100
      continue
    }
    if (row.status === 'failed') continue
    if (row.status === 'waiting') continue
    if (row.total != null && row.total > 0 && row.done != null) {
      sum += Math.min(100, Math.round((row.done / row.total) * 100))
      continue
    }
    sum += 35
  }
  return Math.round(sum / sources.length)
}

export function initCorrelationProgress(phaseLabel: string): void {
  const sources = listCorrelationSources().map((s) => ({
    sourceId: s.sourceId,
    fileName: s.fileName,
    kind: s.kind,
    status: 'waiting' as const,
    phaseLabel: 'Čeká',
    done: null,
    total: null,
    valueCount: null,
  }))
  state = {
    active: true,
    aggregatePercent: 0,
    phaseLabel,
    liveAnnouncement: phaseLabel,
    startedAt: Date.now(),
    sources,
  }
  bump()
}

export function reportCorrelationSessionPhase(phaseLabel: string): void {
  state = {
    ...state,
    phaseLabel,
    liveAnnouncement: phaseLabel,
  }
  bump()
}

export function markCorrelationSourceActive(sourceId: string, phaseLabel = 'Analyzuji…'): void {
  const nextSources = state.sources.map((row) =>
    row.sourceId === sourceId
      ? { ...row, status: 'active' as const, phaseLabel, done: 0, total: null }
      : row,
  )
  state = {
    ...state,
    phaseLabel: 'Analyzuji společně',
    sources: nextSources,
    aggregatePercent: computeAggregate(nextSources),
  }
  bump()
}

export function reportCorrelationSourceProgress(
  sourceId: string,
  phase: string,
  done: number,
  total: number,
): void {
  const label = humanPhase(phase, done, total)
  const nextSources = state.sources.map((row) =>
    row.sourceId === sourceId
      ? { ...row, status: 'active' as const, phaseLabel: label, done, total }
      : row,
  )
  state = {
    ...state,
    sources: nextSources,
    aggregatePercent: computeAggregate(nextSources),
  }
  bump()
}

export function markCorrelationSourceDone(sourceId: string, valueCount: number): void {
  const nextSources = state.sources.map((row) =>
    row.sourceId === sourceId
      ? {
          ...row,
          status: 'done' as const,
          phaseLabel: 'Hotovo',
          done: row.total,
          valueCount,
        }
      : row,
  )
  state = {
    ...state,
    sources: nextSources,
    aggregatePercent: computeAggregate(nextSources),
    liveAnnouncement: `${nextSources.find((r) => r.sourceId === sourceId)?.fileName ?? sourceId} hotovo`,
  }
  bump()
}

export function markCorrelationSourceFailed(sourceId: string, message: string): void {
  const nextSources = state.sources.map((row) =>
    row.sourceId === sourceId
      ? { ...row, status: 'failed' as const, phaseLabel: message, done: null, total: null }
      : row,
  )
  state = {
    ...state,
    sources: nextSources,
    aggregatePercent: computeAggregate(nextSources),
    liveAnnouncement: message,
  }
  bump()
}

export function finishCorrelationProgress(success: boolean, phaseLabel: string): void {
  state = {
    ...state,
    active: false,
    aggregatePercent: success ? 100 : state.aggregatePercent,
    phaseLabel,
    liveAnnouncement: phaseLabel,
  }
  bump()
}
