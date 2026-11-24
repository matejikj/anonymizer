/**
 * T38 — PIM (IP proto 103). Baseline: identify + map Hello holdtime region conservatively;
 * Register / Join-Prune bodies masked (encoded address formats need full dictionary).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import { maskBytes } from './common.ts'

export const IPPROTO_PIM = 103

export function sanitizePim(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; lastCoveredOffset: number } {
  void mapping
  const coverage: LayerCoverage[] = []
  const len = data.length - offset
  if (len < 4) {
    coverage.push({ protocol: 'pim', offset, length: len, status: 'malformed' })
    return { coverage, lastCoveredOffset: offset }
  }
  // Ver(4bits)|Type(4bits) Reserved Checksum
  coverage.push({ protocol: 'pim', offset, length: 4, status: 'covered' })
  if (len > 4) {
    maskBytes(collector, intents, packetIndex, offset + 4, len - 4, 'pim-body', 'pim')
    coverage.push({
      protocol: 'pim-body',
      offset: offset + 4,
      length: len - 4,
      status: 'redacted',
    })
  }
  return { coverage, lastCoveredOffset: offset + len }
}
