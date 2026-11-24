/**
 * Wraps legacy protocols/types ProtocolModule as a kernel module (facts from decode+collect).
 */

import type { ProtocolModule as LegacyProtocolModule, DecodeContext } from '../../protocols/types'
import { MAX_DECODE_DEPTH } from '../../protocols/types'
import type { KernelProtocolModule } from '../protocolModule'
import type { AnalyzeContext, BorrowedByteView, ProbeContext, ProbeResult } from '../types'
import { defaultDescriptor } from '../manifest'
import type { FactWriter } from '../factWriter'
import type { ProtocolLayer, DispatchSelector } from '../types'

export function wrapLegacyProtocolModule(input: {
  legacy: LegacyProtocolModule
  layer: ProtocolLayer
  selectors: readonly DispatchSelector[]
  title: string
  priority?: number
  specRefs?: readonly string[]
}): KernelProtocolModule {
  const descriptor = defaultDescriptor({
    id: input.legacy.id,
    layer: input.layer,
    selectors: input.selectors,
    title: input.title,
    priority: input.priority,
    specRefs: input.specRefs,
  })

  return {
    descriptor,
    probe(view: BorrowedByteView, context: ProbeContext): ProbeResult {
      const ctx: DecodeContext = {
        depthBudget: MAX_DECODE_DEPTH - context.nestingDepth,
        baseOffset: view.byteOffset,
        hint: context.linkType,
      }
      const slice = view.bytes.subarray(0, view.byteLength)
      return input.legacy.probe(slice, ctx)
        ? { decision: 'claim', reasonCode: 'legacy-probe' }
        : { decision: 'no', reasonCode: 'legacy-probe-miss' }
    },
    analyze(view: BorrowedByteView, context: AnalyzeContext, out: FactWriter): void {
      const ctx: DecodeContext = {
        depthBudget: MAX_DECODE_DEPTH - context.nestingDepth,
        baseOffset: view.byteOffset,
        hint: context.linkType,
      }
      const slice = view.bytes.subarray(0, view.byteLength)
      if (!input.legacy.probe(slice, ctx)) return
      const node = input.legacy.decode(slice, ctx)
      const rootFact = out.coverage({
        protocolId: node.protocolId,
        packetIndex: context.packetIndex,
        logicalMessageId: context.logicalMessageId,
        parentFactId: 0,
        spanOffset: node.range.start,
        spanLength: Math.max(0, node.range.end - node.range.start),
        status: node.issues.length > 0 ? 'malformed' : 'covered',
        recognition: node.issues.length > 0 ? 'malformed' : 'recognized',
        reasonCode: node.issues[0],
      })
      // Entity collection is projected from the same decode tree (parity with analysis.collect).
      void rootFact
      input.legacy.collect(node, {
        addIpv4() { /* projected via discovery intents in legacy sanitize path */ },
        addIpv6() {},
        addMac() {},
        addHostname() {},
        addPort() {},
        addVlan() {},
      }, context.packetIndex)
    },
  }
}
