/**
 * Port for rebuilding PCAP preview/export plan after level change.
 */

import type { PcapAnonymizationLevel } from './pcapAnonymizationLevel'

export interface PcapPlanRebuildResult {
  /** Monotonic generation token for this rebuild request. */
  generation: number
  /** True when rebuild completed and was still the latest generation. */
  applied: boolean
}

export interface PcapPlanRebuildPort {
  /** Latest scheduled generation (always increases on schedule). */
  currentGeneration(): number
  /** Generation of the last successfully applied plan. */
  activeGeneration(): number
  /** True when a completed rebuild for `generation` may update the live plan. */
  shouldApply(generation: number): boolean
  /**
   * Mark plan stale immediately and rebuild for `level`.
   * Late/async results must call shouldApply before committing.
   */
  rebuildPlan(level: PcapAnonymizationLevel): Promise<PcapPlanRebuildResult>
}
