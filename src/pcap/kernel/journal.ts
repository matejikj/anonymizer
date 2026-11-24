/**
 * SemanticJournal — canonical interpretation record for one processing generation.
 * Packed-friendly structure; object form is the debug/test adapter.
 */

import type { LayerCoverage } from '../sanitize/types'
import type { TransformationIntent } from '../discovery/types'
import type { ProtocolFactHeader, ProtocolIdentityRef, RecognitionState } from './types'
import type { SymbolicOperation } from './operations'
import type { DiagnosticImpactEntry } from './diagnosticImpact'
import type { FrozenPacketPlan } from './frozenPlan'
import { SourceSpanMap } from './coordinates'
import { SessionBudgetAccountant } from './budgets'

export interface JournalFact extends ProtocolFactHeader {
  readonly factId: number
  readonly fieldId?: string
  readonly identityRef?: ProtocolIdentityRef
  readonly coverageStatus?: LayerCoverage['status']
  readonly reasonCode?: string
}

export interface PacketJournalRecord {
  readonly packetIndex: number
  readonly packetNumber: number
  readonly bufferLength: number
  readonly drop: boolean
  readonly truncatedLength?: number
  readonly coverage: readonly LayerCoverage[]
  readonly issues: readonly string[]
  readonly intents: readonly TransformationIntent[]
  readonly ops: readonly SymbolicOperation[]
  readonly factIds: readonly number[]
}

export interface SemanticJournal {
  readonly generationId: string
  readonly sourceId: string
  readonly engineVersion: string
  readonly facts: readonly JournalFact[]
  readonly packets: readonly PacketJournalRecord[]
  readonly spanMap: SourceSpanMap
  readonly impacts: readonly DiagnosticImpactEntry[]
  readonly recognitionCounts: ReadonlyMap<RecognitionState, number>
}

/** Kernel-native frozen plan from one journal row (no legacy deferred bridge). */
export function frozenPlanFromJournalRecord(record: PacketJournalRecord): FrozenPacketPlan {
  return {
    packetIndex: record.packetIndex,
    packetNumber: record.packetNumber,
    bufferLength: record.bufferLength,
    drop: record.drop,
    truncatedLength: record.truncatedLength,
    coverage: record.coverage,
    issues: record.issues,
    intents: record.intents,
    ops: record.ops,
  }
}

export const KERNEL_ENGINE_VERSION = 't01-1.0.0'

export class SemanticJournalBuilder {
  private nextFactId = 1
  private readonly facts: JournalFact[] = []
  private readonly packets: PacketJournalRecord[] = []
  private readonly impacts: DiagnosticImpactEntry[] = []
  private readonly recognitionCounts = new Map<RecognitionState, number>()
  readonly spanMap = new SourceSpanMap()
  readonly generationId: string
  readonly sourceId: string
  private readonly budgets: SessionBudgetAccountant

  constructor(
    generationId: string,
    sourceId: string,
    budgets: SessionBudgetAccountant = new SessionBudgetAccountant(),
  ) {
    this.generationId = generationId
    this.sourceId = sourceId
    this.budgets = budgets
  }

  addFact(input: Omit<JournalFact, 'factId'>): number {
    const factId = this.nextFactId++
    this.facts.push({ ...input, factId })
    this.noteRecognition(input.recognition)
    // Approximate packed size: header ints + optional short codes (not payload).
    this.budgets.reserve('journal', 64)
    return factId
  }

  /**
   * Histogram-only recognition tick — used when projecting high-volume L2–L4 coverage
   * without allocating a JournalFact row per layer (would exceed journalMaxBytes on 100 MiB).
   */
  noteRecognition(recognition: RecognitionState): void {
    this.recognitionCounts.set(
      recognition,
      (this.recognitionCounts.get(recognition) ?? 0) + 1,
    )
  }

  /** Fact ids recorded for one packet (T02.S4 SIPREC and other kernel-native spans). */
  factIdsForPacket(packetIndex: number): readonly number[] {
    const ids: number[] = []
    for (const fact of this.facts) {
      if (fact.packetIndex === packetIndex) ids.push(fact.factId)
    }
    return ids
  }

  addPacket(record: PacketJournalRecord): void {
    this.packets.push(record)
    // Ops descriptors + coverage rows — not mask fill buffers.
    // Legacy intents stay on discovery.packetDiscovery (R09); do not budget-duplicate them.
    const approx =
      96 +
      record.ops.length * 48 +
      record.coverage.length * 24 +
      (record.ops.length > 0 ? record.intents.length * 48 : 0) +
      record.issues.length * 16
    this.budgets.reserve('journal', approx)
  }

  addImpact(entry: DiagnosticImpactEntry): void {
    this.impacts.push(entry)
  }

  freeze(): SemanticJournal {
    return {
      generationId: this.generationId,
      sourceId: this.sourceId,
      engineVersion: KERNEL_ENGINE_VERSION,
      facts: this.facts,
      packets: this.packets,
      spanMap: this.spanMap,
      impacts: this.impacts,
      recognitionCounts: this.recognitionCounts,
    }
  }

  budgetSnapshot() {
    return this.budgets.snapshot()
  }
}
