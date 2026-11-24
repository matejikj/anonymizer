/**
 * R09 / T-01.B — wire meta for PatchCollector.maskRangeDeferred() so journal carries mask/secret ops.
 */

import { createProtocolNeutralMaskFill } from './maskFill'
import type { PatchCollector } from './PatchCollector'
import type { DeferredPatchMeta } from './types'

/** Journal fields for deterministic protocol-neutral mask deferrals. */
export function deferredProtocolNeutralMaskMeta(
  protocol: string,
  packetIndex: number,
  domain: string,
  reasonCode: string,
): Partial<DeferredPatchMeta> {
  return {
    fallbackKind: 'binary-mask',
    protocol,
    packetIndex,
    maskDomain: domain,
    maskFillKind: 'protocol-neutral',
    reasonCode,
  }
}

export function maskRangeDeferredProtocolNeutral(
  collector: PatchCollector,
  offset: number,
  length: number,
  packetIndex: number,
  domain: string,
  protocol: string,
  reasonCode?: string,
): void {
  if (length <= 0) return
  const code = reasonCode ?? domain
  collector.maskRangeDeferred(
    offset,
    length,
    () =>
      createProtocolNeutralMaskFill({
        length,
        packetIndex,
        offset,
        domain,
      }),
    deferredProtocolNeutralMaskMeta(protocol, packetIndex, domain, code),
  )
}
