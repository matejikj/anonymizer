/**
 * T63.2 — scan export bytes for surviving field-policy canaries (value-free result).
 */

import { bufferContainsCanary } from './canaryBytes'
import type { InjectedCanary } from './canaryInject'

export interface SurvivingCanary {
  readonly fieldPath: string
  readonly offset: number
  readonly length: number
}

/** Return canaries still present in `exported` — empty means conformance pass for those fields. */
export function findSurvivingCanaries(
  exported: Uint8Array,
  injected: readonly InjectedCanary[],
): readonly SurvivingCanary[] {
  const survivors: SurvivingCanary[] = []
  for (const item of injected) {
    if (bufferContainsCanary(exported, item.canary)) {
      survivors.push({
        fieldPath: item.fieldPath,
        offset: item.offset,
        length: item.length,
      })
    }
  }
  return survivors
}
