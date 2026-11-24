/**
 * T31 — sanitize path for RND Dispatch Lite (compiled from descriptor).
 */

import type { PatchCollector } from './PatchCollector.ts'
import type { MappingLike } from '../anonymization/mapping.ts'
import type { AppLayerResult } from './types.ts'
import {
  descriptorPortHint,
  rndDispatchLiteDescriptor,
  sanitizeFromDescriptor,
} from '../protocols/descriptors/index.ts'

export function sanitizeRndDispatchLite(
  buffer: Uint8Array,
  offset: number,
  length: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
): AppLayerResult | null {
  if (!descriptorPortHint(rndDispatchLiteDescriptor, dstPort, 'udp')) return null
  return sanitizeFromDescriptor(
    rndDispatchLiteDescriptor,
    buffer,
    offset,
    length,
    collector,
    mapping,
  )
}
