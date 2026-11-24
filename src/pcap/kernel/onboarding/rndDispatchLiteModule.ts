/**
 * T31 — kernel module projection of RND Dispatch Lite descriptor (facts for catalog/matrix).
 */

import type { KernelProtocolModule } from '../protocolModule'
import { defaultDescriptor } from '../manifest'
import type { AnalyzeContext, BorrowedByteView, ProbeContext, ProbeResult } from '../types'
import type { FactWriter } from '../factWriter'
import {
  RND_DISPATCH_LITE_MAGIC,
  RND_DISPATCH_LITE_UDP_PORT,
  rndDispatchLiteDescriptor,
} from '../../protocols/descriptors/rndDispatchLite.ts'

export const rndDispatchLiteModule: KernelProtocolModule = {
  descriptor: defaultDescriptor({
    id: 'rnd-dispatch-lite',
    layer: 'application',
    selectors: [{ kind: 'udp-port', value: RND_DISPATCH_LITE_UDP_PORT }],
    title: rndDispatchLiteDescriptor.title,
    priority: 114,
    specRefs: [...rndDispatchLiteDescriptor.specRefs],
  }),

  probe(view: BorrowedByteView, _context: ProbeContext): ProbeResult {
    const magic = RND_DISPATCH_LITE_MAGIC
    if (view.byteLength < magic.length) {
      return { decision: 'need-more', reasonCode: 'rnd-dispatch-short' }
    }
    for (let i = 0; i < magic.length; i++) {
      if (view.bytes[i] !== magic[i]) {
        return { decision: 'no', reasonCode: 'rnd-dispatch-magic-miss' }
      }
    }
    return { decision: 'claim', reasonCode: 'rnd-dispatch-magic' }
  },

  analyze(view: BorrowedByteView, context: AnalyzeContext, out: FactWriter): void {
    const headerLen = rndDispatchLiteDescriptor.framing.headerLength
    if (view.byteLength < headerLen) {
      out.coverage({
        protocolId: 'rnd-dispatch-lite',
        packetIndex: context.packetIndex,
        logicalMessageId: context.logicalMessageId,
        parentFactId: 0,
        spanOffset: 0,
        spanLength: view.byteLength,
        status: 'malformed',
        recognition: 'malformed',
        reasonCode: 'rnd-dispatch-truncated',
      })
      return
    }

    const src =
      ((view.bytes[8]! << 16) | (view.bytes[9]! << 8) | view.bytes[10]!) >>> 0
    const dst =
      ((view.bytes[11]! << 16) | (view.bytes[12]! << 8) | view.bytes[13]!) >>> 0

    out.coverage({
      protocolId: 'rnd-dispatch-lite',
      packetIndex: context.packetIndex,
      logicalMessageId: context.logicalMessageId,
      parentFactId: 0,
      spanOffset: 0,
      spanLength: headerLen,
      status: 'covered',
      recognition: 'recognized',
    })

    const emitRadio = (spanOffset: number, id: number) => {
      const canonical = String(id)
      const constraint = { kind: 'radio-id-wire' as const, bitWidth: 24 as const }
      out.identity({
        protocolId: 'rnd-dispatch-lite',
        packetIndex: context.packetIndex,
        logicalMessageId: context.logicalMessageId,
        parentFactId: 0,
        spanOffset,
        spanLength: 3,
        identity: { category: 'radioId', canonical, constraint },
        mapOp: {
          kind: 'map',
          packetIndex: context.packetIndex,
          offset: spanOffset,
          length: 3,
          category: 'radioId',
          canonical,
          constraint,
          encoder: 'u24-be',
        },
      })
    }
    emitRadio(8, src)
    emitRadio(11, dst)

    // siteId (opaque-id / bytes) is applied on the sanitize descriptor path — same
    // deferred mapping pattern as DMR radio IDs when kernel encoders lack raw-bytes.

    if (view.byteLength > headerLen) {
      out.operation({
        kind: 'mask',
        packetIndex: context.packetIndex,
        offset: headerLen,
        length: view.byteLength - headerLen,
        fillKind: 'protocol-neutral',
        domain: 'rnd-dispatch-lite',
        reasonCode: 'rnd-dispatch-body',
      })
      out.impact({
        protocolId: 'rnd-dispatch-lite',
        packetIndex: context.packetIndex,
        logicalMessageId: context.logicalMessageId,
        byteCount: view.byteLength - headerLen,
        reason: 'content-redacted',
        disposition: 'mask',
      })
    }
  },
}
