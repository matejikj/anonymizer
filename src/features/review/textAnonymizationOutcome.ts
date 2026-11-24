/**
 * T10 / T71 — text-mode anonymization outcome view model (pure TS).
 * Gate comes from the text disposition ledger; disabled categories are not exposed.
 */

import { cs } from '../../i18n/cs.ts'
import type { IncidentLogSnapshot } from '../../domain/anonymizationIncident.ts'
import type { Category, Entity } from '../../domain/types.ts'
import { resolveTextExportGate, type GateResult } from '../../pcap/trust/exportGate.ts'
import { CATEGORY_LABELS } from './categoryLabels.ts'
import {
  computeAliasSuppressedSummary,
  summarizeCategories,
  type CategoryMasterMap,
} from './entityState.ts'
import {
  emptyTextDispositionAggregate,
  gateFromTextDispositionLedger,
  withAliasSuppressions,
  withFailedRules,
  type TextDispositionLedgerAggregate,
} from '../../engine/freeText/textDispositionLedger.ts'

export interface TextOutcomeCategoryRow {
  readonly category: Category
  readonly label: string
  readonly uniqueCount: number
  readonly occurrenceCount: number
  readonly enabledUnique: number
}

export interface TextOutcomeIncidentRow {
  readonly lineNumber?: number
  readonly reasonLabel: string
  readonly fallbackLabel: string
}

export interface TextAnonymizationOutcome {
  readonly summarySentence: string
  readonly gate: GateResult
  readonly gateLabel: string
  readonly categories: readonly TextOutcomeCategoryRow[]
  readonly failedRuleIds: readonly string[]
  readonly incidents: readonly TextOutcomeIncidentRow[]
  readonly incidentTotal: number
  readonly incidentMoreCount: number
  readonly oversizedLines: readonly number[]
  readonly noFindings: boolean
  readonly textDispositionLedger: TextDispositionLedgerAggregate
}

const MAX_INCIDENTS = 50

function gateLabel(gate: GateResult): string {
  switch (gate) {
    case 'AI_READY':
      return cs.pcap.coverageUx.gateAiReady
    case 'AI_READY_WITH_GAPS':
      return cs.pcap.coverageUx.gateAiReadyWithGaps
    case 'NOT_AI_READY':
      return cs.pcap.coverageUx.gateNotAiReady
    default:
      return cs.pcap.coverageUx.gateNotAiReady
  }
}

function reasonLabel(reason: string): string {
  const map = cs.pcap.outcome.incidentReason as Record<string, string>
  return map[reason] ?? cs.pcap.outcome.incidentReason.unknown
}

function fallbackLabel(fallback: string): string {
  const map = cs.pcap.outcome.incidentFallback as Record<string, string>
  return map[fallback] ?? fallback
}

export function buildTextAnonymizationOutcome(input: {
  readonly entities: readonly Entity[]
  readonly categoryMasters: CategoryMasterMap
  readonly failedRuleIds: readonly string[]
  readonly incidents?: IncidentLogSnapshot | null
  readonly oversizedLines?: readonly number[]
  readonly textDispositionLedger?: TextDispositionLedgerAggregate | null
}): TextAnonymizationOutcome {
  const entities = [...input.entities]
  const suppressed = computeAliasSuppressedSummary(entities, input.categoryMasters)
  let ledger =
    input.textDispositionLedger ?? emptyTextDispositionAggregate()
  ledger = withAliasSuppressions(ledger, suppressed.entityCount)
  ledger = withFailedRules(ledger, input.failedRuleIds.length)
  const ledgerGate = gateFromTextDispositionLedger(ledger)

  const gateResult = resolveTextExportGate({
    failedRuleIds: input.failedRuleIds,
    incidentCount: input.incidents?.totalFailures ?? 0,
    ledgerGate,
    maskTokenCount: ledger.byDisposition.mask,
  })
  const gate = gateResult.gate
  const noFindings = entities.length === 0

  const categories = summarizeCategories(entities, input.categoryMasters)
    .filter((c) => c.uniqueCount > 0)
    .map((c) => ({
      category: c.category,
      label: CATEGORY_LABELS[c.category],
      uniqueCount: c.uniqueCount,
      occurrenceCount: c.occurrenceCount,
      enabledUnique: c.masterEnabled ? c.enabledUnique : 0,
    }))

  const incidentRows: TextOutcomeIncidentRow[] = (input.incidents?.incidents ?? [])
    .slice(0, MAX_INCIDENTS)
    .map((inc) => ({
      lineNumber: inc.lineNumber,
      reasonLabel: reasonLabel(inc.reason),
      fallbackLabel: fallbackLabel(inc.fallback),
    }))

  const incidentTotal = input.incidents?.totalFailures ?? incidentRows.length
  const incidentMoreCount = Math.max(0, incidentTotal - incidentRows.length)
  const oversizedLines = input.oversizedLines ?? []

  const catLabels = categories.map((c) => c.label).slice(0, 6)
  const protocols =
    catLabels.length === 0 ? cs.pcap.outcome.summaryNoProtocols : catLabels.join(', ')

  let summarySentence: string
  if (noFindings && gate === 'AI_READY') {
    summarySentence = cs.pcap.outcome.textNoFindings
  } else if (gate === 'AI_READY') {
    summarySentence = `${cs.pcap.outcome.summaryLevelDiagnostic} ${cs.pcap.outcome.summaryAiReady.replace('{protocols}', protocols)}`
  } else if (gate === 'AI_READY_WITH_GAPS') {
    summarySentence = `${cs.pcap.outcome.summaryLevelDiagnostic} ${cs.pcap.outcome.summaryWithGaps
      .replace('{protocols}', protocols)
      .replace('{gaps}', cs.pcap.outcome.summaryGenericGaps)}`
  } else {
    summarySentence = `${cs.pcap.outcome.summaryLevelDiagnostic} ${cs.pcap.outcome.summaryInternalFallback.replace('{protocols}', protocols)}`
  }

  return {
    summarySentence,
    gate,
    gateLabel: gateLabel(gate),
    categories,
    failedRuleIds: [...input.failedRuleIds],
    incidents: incidentRows,
    incidentTotal,
    incidentMoreCount,
    oversizedLines,
    noFindings,
    textDispositionLedger: ledger,
  }
}
