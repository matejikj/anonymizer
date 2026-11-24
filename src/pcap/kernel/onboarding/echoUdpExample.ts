/**
 * T-01.6 onboarding example — synthetic UDP “echo-id” protocol.
 * Demonstrates module + manifest + corpus without touching central sanitize switches.
 *
 * Wire: magic "ECHO" (4) + 24-bit radio id (3) + opaque payload.
 * Identity is mapped; payload masked; framing preserved.
 */

import type { KernelProtocolModule } from '../protocolModule'
import { defaultDescriptor } from '../manifest'
import type { AnalyzeContext, BorrowedByteView, ProbeContext, ProbeResult } from '../types'
import type { FactWriter } from '../factWriter'

/** Non-standard UDP port used only in synthetic fixtures. */
export const ECHO_UDP_EXAMPLE_PORT = 49_991
export const ECHO_UDP_MAGIC = new TextEncoder().encode('ECHO')

export const echoUdpExampleModule: KernelProtocolModule = {
  descriptor: defaultDescriptor({
    id: 'echo-udp-example',
    layer: 'application',
    selectors: [{ kind: 'udp-port', value: ECHO_UDP_EXAMPLE_PORT }],
    title: 'Echo UDP example (T-01 onboarding)',
    priority: 50,
    specRefs: ['tasks/anonymizer-robustness/T-01-unified-streaming-protocol-kernel.md'],
  }),

  probe(view: BorrowedByteView, _context: ProbeContext): ProbeResult {
    if (view.byteLength < 7) return { decision: 'need-more', reasonCode: 'echo-too-short' }
    const b = view.bytes
    for (let i = 0; i < 4; i++) {
      if (b[i] !== ECHO_UDP_MAGIC[i]) return { decision: 'no', reasonCode: 'echo-magic-miss' }
    }
    return { decision: 'claim', reasonCode: 'echo-magic' }
  },

  analyze(view: BorrowedByteView, context: AnalyzeContext, out: FactWriter): void {
    if (view.byteLength < 7) {
      out.coverage({
        protocolId: 'echo-udp-example',
        packetIndex: context.packetIndex,
        logicalMessageId: context.logicalMessageId,
        parentFactId: 0,
        spanOffset: 0,
        spanLength: view.byteLength,
        status: 'malformed',
        recognition: 'malformed',
        reasonCode: 'echo-truncated',
      })
      return
    }
    const id = ((view.bytes[4]! << 16) | (view.bytes[5]! << 8) | view.bytes[6]!) >>> 0
    const canonical = String(id)
    const constraint = { kind: 'radio-id-wire' as const, bitWidth: 24 as const }
    out.coverage({
      protocolId: 'echo-udp-example',
      packetIndex: context.packetIndex,
      logicalMessageId: context.logicalMessageId,
      parentFactId: 0,
      spanOffset: 0,
      spanLength: 7,
      status: 'covered',
      recognition: 'recognized',
    })
    out.identity({
      protocolId: 'echo-udp-example',
      packetIndex: context.packetIndex,
      logicalMessageId: context.logicalMessageId,
      parentFactId: 0,
      spanOffset: 4,
      spanLength: 3,
      identity: {
        category: 'radioId',
        canonical,
        constraint,
      },
      mapOp: {
        kind: 'map',
        packetIndex: context.packetIndex,
        offset: 4,
        length: 3,
        category: 'radioId',
        canonical,
        constraint,
        encoder: 'u24-be',
      },
    })
    if (view.byteLength > 7) {
      out.operation({
        kind: 'mask',
        packetIndex: context.packetIndex,
        offset: 7,
        length: view.byteLength - 7,
        fillKind: 'protocol-neutral',
        domain: 'echo-udp-example',
        reasonCode: 'echo-payload',
      })
      out.impact({
        protocolId: 'echo-udp-example',
        packetIndex: context.packetIndex,
        logicalMessageId: context.logicalMessageId,
        byteCount: view.byteLength - 7,
        reason: 'content-redacted',
        disposition: 'mask',
      })
    }
  },
}

/** Build echo-id application payload (tests / corpus). */
export function buildEchoUdpDatagram(identity: number, payload: Uint8Array = new Uint8Array(0)): Uint8Array {
  const id = identity & 0xffffff
  const body = new Uint8Array(7 + payload.length)
  body.set(ECHO_UDP_MAGIC, 0)
  body[4] = (id >>> 16) & 0xff
  body[5] = (id >>> 8) & 0xff
  body[6] = id & 0xff
  body.set(payload, 7)
  return body
}
