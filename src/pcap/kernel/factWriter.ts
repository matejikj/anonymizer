/**
 * FactWriter — hot-path append API for protocol analyzers.
 */

import type { LayerCoverage } from '../sanitize/types'
import type { ProtocolIdentityRef, RecognitionState } from './types'
import type { SymbolicOperation } from './operations'
import type { DiagnosticImpactEntry } from './diagnosticImpact'
import type { SemanticJournalBuilder } from './journal'

export interface FactWriter {
  structuralField(input: {
    protocolId: string
    packetIndex: number
    logicalMessageId: number
    parentFactId: number
    spanOffset: number
    spanLength: number
    fieldId: string
    recognition?: RecognitionState
  }): number

  identity(input: {
    protocolId: string
    packetIndex: number
    logicalMessageId: number
    parentFactId: number
    spanOffset: number
    spanLength: number
    identity: ProtocolIdentityRef
    mapOp: Extract<SymbolicOperation, { kind: 'map' }>
  }): number

  coverage(input: {
    protocolId: string
    packetIndex: number
    logicalMessageId: number
    parentFactId: number
    spanOffset: number
    spanLength: number
    status: LayerCoverage['status']
    recognition: RecognitionState
    reasonCode?: string
  }): number

  operation(op: SymbolicOperation): void
  impact(entry: DiagnosticImpactEntry): void
}

export function createFactWriter(
  journal: SemanticJournalBuilder,
  packetOps: SymbolicOperation[],
): FactWriter {
  return {
    structuralField(input) {
      return journal.addFact({
        protocolId: input.protocolId,
        packetIndex: input.packetIndex,
        logicalMessageId: input.logicalMessageId,
        parentFactId: input.parentFactId,
        spanOffset: input.spanOffset,
        spanLength: input.spanLength,
        fieldId: input.fieldId,
        recognition: input.recognition ?? 'recognized',
      })
    },
    identity(input) {
      packetOps.push(input.mapOp)
      return journal.addFact({
        protocolId: input.protocolId,
        packetIndex: input.packetIndex,
        logicalMessageId: input.logicalMessageId,
        parentFactId: input.parentFactId,
        spanOffset: input.spanOffset,
        spanLength: input.spanLength,
        identityRef: input.identity,
        recognition: 'recognized',
      })
    },
    coverage(input) {
      return journal.addFact({
        protocolId: input.protocolId,
        packetIndex: input.packetIndex,
        logicalMessageId: input.logicalMessageId,
        parentFactId: input.parentFactId,
        spanOffset: input.spanOffset,
        spanLength: input.spanLength,
        coverageStatus: input.status,
        recognition: input.recognition,
        reasonCode: input.reasonCode,
      })
    },
    operation(op) {
      packetOps.push(op)
    },
    impact(entry) {
      journal.addImpact(entry)
    },
  }
}
