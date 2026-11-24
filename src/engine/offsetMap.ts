import type { OffsetMap, PackedMatchIndex } from '../domain/types.ts'
import type { ReplacementPlan } from './transform.ts'
import { fenwickPrefix, fenwickUpdate } from './fenwick.ts'

/**
 * Bidirectional offset map using Fenwick prefix sums of length deltas
 * (ARCHITECTURE §6 / §7.5).
 */
export function createOffsetMap(
  index: PackedMatchIndex,
  plan: ReplacementPlan,
): OffsetMap {
  return {
    originalToOutput(originalOffset: number): number {
      // Sum deltas of matches that fully end at or before originalOffset.
      let lo = 0
      let hi = index.starts.length
      while (lo < hi) {
        const mid = (lo + hi) >>> 1
        if (index.starts[mid]! + index.lengths[mid]! <= originalOffset) lo = mid + 1
        else hi = mid
      }
      return originalOffset + fenwickPrefix(plan.fenwick, lo)
    },

    outputToOriginal(outputOffset: number): number {
      // Find largest original O such that originalToOutput(O) <= outputOffset.
      let lo = 0
      let hi = estimateOriginalLength(index, plan, outputOffset)
      while (lo < hi) {
        const mid = (lo + hi + 1) >>> 1
        if (this.originalToOutput(mid) <= outputOffset) lo = mid
        else hi = mid - 1
      }
      return lo
    },

    updateMatch(matchIndex: number, lengthDelta: number): void {
      const prev = plan.lengthDeltas[matchIndex]!
      const delta = lengthDelta - prev
      plan.lengthDeltas[matchIndex] = lengthDelta
      fenwickUpdate(plan.fenwick, matchIndex, delta)
    },
  }
}

function estimateOriginalLength(
  index: PackedMatchIndex,
  plan: ReplacementPlan,
  outputOffset: number,
): number {
  if (index.starts.length === 0) return outputOffset
  const last = index.starts.length - 1
  const lastEnd = index.starts[last]! + index.lengths[last]!
  const totalDelta = fenwickPrefix(plan.fenwick, index.starts.length)
  return Math.max(outputOffset - totalDelta, lastEnd, outputOffset)
}
