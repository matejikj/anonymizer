/**
 * T31 — compiled-in descriptor registry (no dynamic loading).
 */

import type { WireProtocolDescriptor } from './types.ts'
import { validateWireProtocolDescriptor } from './validate.ts'
import { rndDispatchLiteDescriptor } from './rndDispatchLite.ts'

const DESCRIPTORS: readonly WireProtocolDescriptor[] = [rndDispatchLiteDescriptor]

export function listWireProtocolDescriptors(): readonly WireProtocolDescriptor[] {
  return DESCRIPTORS
}

export function getWireProtocolDescriptor(id: string): WireProtocolDescriptor | undefined {
  return DESCRIPTORS.find((d) => d.id === id)
}

/** Fail CI if any shipped descriptor is invalid. */
export function assertAllDescriptorsValid(): void {
  for (const desc of DESCRIPTORS) {
    const result = validateWireProtocolDescriptor(desc)
    if (!result.ok) {
      const detail = result.issues.map((i) => `${i.path}:${i.code}`).join('; ')
      throw new Error(`Invalid protocol descriptor ${desc.id}: ${detail}`)
    }
  }
}
