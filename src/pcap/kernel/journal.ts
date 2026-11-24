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

/** Approximate V8 sizes (64-bit, no pointer compression) — conservative for the browser. */
const JOURNAL_RECORD_BYTES = 112
const ARRAY_HEADER_BYTES = 32
const POINTER_BYTES = 8
/** TransformationIntent / LayerCoverage row (plain objects, ~8 fields) and issue-token pointer. */
const INTENT_BYTES = 80
const COVERAGE_ROW_BYTES = 64
const NO_FACT_IDS: readonly number[] = []

function isShareableOp(op: SymbolicOperation): boolean {
  return op.kind === 'map' || op.kind === 'mask' || op.kind === 'secret' || op.kind === 'preserve'
}

/** Object bytes of one op; identity strings and constraints are interned (shared). */
function symbolicOpBytes(op: SymbolicOperation): number {
  switch (op.kind) {
    case 'map':
      return 96
    case 'fingerprint':
      return 152
    case 'fixed':
      // op object + Uint8Array view + ArrayBuffer + the bytes themselves
      return 56 + 64 + 32 + op.data.byteLength
    default:
      return 80
  }
}

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
  /** Ops shared across packets (identityIntern) — budgeted once, on first sight. */
  private readonly countedSharedOps = new Set<SymbolicOperation>()
  private readonly countedLists = new Set<readonly unknown[]>()

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
    let ids: number[] | undefined
    for (const fact of this.facts) {
      if (fact.packetIndex === packetIndex) (ids ??= []).push(fact.factId)
    }
    // Most packets carry no kernel facts — one shared empty list instead of one per packet.
    return ids ?? NO_FACT_IDS
  }

  addPacket(record: PacketJournalRecord): void {
    this.packets.push(record)
    // Bytes retained per packet: the record, its ops and its per-packet discovery lists (the
    // same objects packetDiscovery holds — this is the only budget that bounds them). Ops and
    // coverage / issue lists shared across the packets of a flow (identityIntern) count once;
    // intents carry their packetIndex and are always per packet. Mask fills are regenerated on
    // render, never stored.
    let approx = JOURNAL_RECORD_BYTES + ARRAY_HEADER_BYTES + record.ops.length * POINTER_BYTES
      + record.factIds.length * POINTER_BYTES
      + ARRAY_HEADER_BYTES + record.intents.length * (POINTER_BYTES + INTENT_BYTES)
    approx += this.listBytesOnce(record.coverage, COVERAGE_ROW_BYTES)
    approx += this.listBytesOnce(record.issues, 0)
    for (const op of record.ops) {
      if (isShareableOp(op)) {
        if (this.countedSharedOps.has(op)) continue
        this.countedSharedOps.add(op)
      }
      approx += symbolicOpBytes(op)
    }
    this.budgets.reserve('journal', approx)
  }

  private listBytesOnce(list: readonly unknown[], rowBytes: number): number {
    if (list.length === 0 || this.countedLists.has(list)) return 0
    this.countedLists.add(list)
    return ARRAY_HEADER_BYTES + list.length * (POINTER_BYTES + rowBytes)
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
