/**
 * Kernel ProtocolModule — one analyze() emits facts + symbolic ops for all projections.
 */

import type {
  AnalyzeContext,
  BorrowedByteView,
  ProbeContext,
  ProbeResult,
  ProtocolDescriptor,
} from './types'
import type { FactWriter } from './factWriter'

export interface KernelProtocolModule {
  readonly descriptor: ProtocolDescriptor
  probe(view: BorrowedByteView, context: ProbeContext): ProbeResult
  analyze(view: BorrowedByteView, context: AnalyzeContext, out: FactWriter): void
}
