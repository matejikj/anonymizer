/**
 * T63.2 — inject unique canaries into synthetic frames per field policy.
 * Production helper for the future canaryConformance harness (F1) — no test runner deps.
 */

import {
  fieldPolicyRequiresCanaryAbsence,
  resolveFieldWireSpan,
  type FieldPolicyDescriptor,
} from '../kernel/fieldPolicy'
import { buildFieldCanary } from './canaryBytes'

export interface InjectedCanary {
  readonly fieldPath: string
  readonly offset: number
  readonly length: number
  readonly canary: Uint8Array
}

export interface CanaryInjectionResult {
  readonly frame: Uint8Array
  readonly injected: readonly InjectedCanary[]
}

/**
 * Copy `frame` and overwrite every canary-required field that has a wire locator.
 * Fields without locators are skipped (harness fixtures supply locators as tables grow).
 */
export function injectFieldPolicyCanaries(input: {
  readonly frame: Uint8Array
  readonly protocolOffset: number
  readonly fields: readonly FieldPolicyDescriptor[]
  readonly level?: 'diagnostic' | 'high-privacy'
}): CanaryInjectionResult {
  const frame = new Uint8Array(input.frame)
  const injected: InjectedCanary[] = []

  for (const field of input.fields) {
    if (!fieldPolicyRequiresCanaryAbsence(field, input.level)) continue
    const span = resolveFieldWireSpan(field, frame, input.protocolOffset)
    if (!span) continue
    const canary = buildFieldCanary(field.fieldPath, span.length, field.canaryKind ?? 'binary')
    frame.set(canary, span.offset)
    injected.push({
      fieldPath: field.fieldPath,
      offset: span.offset,
      length: span.length,
      canary,
    })
  }

  return { frame, injected }
}
