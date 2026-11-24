/**
 * T39 — Citrix ICA/CGP (TCP 1494/2598): identify + fail-closed mask (no plaintext pass).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { maskBytes } from './common.ts'

export const CITRIX_ICA_PORT = 1494
export const CITRIX_CGP_PORT = 2598

export function isCitrixPortHint(srcPort: number, dstPort: number): boolean {
  return (
    srcPort === CITRIX_ICA_PORT
    || dstPort === CITRIX_ICA_PORT
    || srcPort === CITRIX_CGP_PORT
    || dstPort === CITRIX_CGP_PORT
  )
}

export function sanitizeCitrix(
  _buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  packetIndex: number,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isCitrixPortHint(srcPort, dstPort) || length < 2) return null
  maskBytes(collector, intents, packetIndex, offset, length, 'citrix-body', 'citrix')
  return {
    coverage: [
      { protocol: 'citrix', offset, length: Math.min(2, length), status: 'covered' },
      { protocol: 'citrix-body', offset, length, status: 'redacted' },
    ],
    issues: ['citrix-identify-mask'],
  }
}
