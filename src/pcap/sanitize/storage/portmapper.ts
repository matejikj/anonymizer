/**
 * T42 — ONC RPC portmapper / rpcbind (TCP/UDP 111): program preserve; port → flow hint.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { maskBytes, readU32be } from './common.ts'
import { sanitizeOncRpcMessage, looksLikeOncRpcCall } from './oncRpc.ts'

export const PORTMAPPER_PORT = 111
export const PMAP_PROG = 100_000

export function isPortmapperPortHint(src: number, dst: number): boolean {
  return src === PORTMAPPER_PORT || dst === PORTMAPPER_PORT
}

export function looksLikePortmapper(
  buffer: Uint8Array,
  offset: number,
  length: number,
): boolean {
  return looksLikeOncRpcCall(buffer, offset, length, PMAP_PROG)
}

export function sanitizePortmapper(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  highPrivacy: boolean,
  intents?: IntentCollector,
  transport: 'tcp' | 'udp' = 'udp',
): AppLayerResult | null {
  if (!isPortmapperPortHint(srcPort, dstPort) && !looksLikePortmapper(buffer, offset, length)) {
    return null
  }

  let lastProc = -1

  const result = sanitizeOncRpcMessage({
    buffer,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
    highPrivacy,
    transport,
    protocol: 'portmapper',
    onCallBody: (bodyOff, bodyLen, prog, _vers, proc) => {
      lastProc = proc
      if (prog !== PMAP_PROG) return
      // GETPORT/DUMP args — preserve program/version/protocol numbers
      void bodyOff
      void bodyLen
    },
    onReplyBody: (bodyOff, bodyLen) => {
      // GETPORT success body is a single u32 port (matched via last CALL or short body)
      if ((lastProc === 3 || bodyLen === 4) && bodyLen >= 4) {
        const port = readU32be(buffer, bodyOff)
        if (port > 0 && port < 65536) {
          intents?.recordPortFlowHint(`tcp/${port}`, 'other')
          intents?.recordPortFlowHint(`udp/${port}`, 'other')
        }
        return
      }
      if (lastProc === 4 /* DUMP */ && bodyLen > 64) {
        maskBytes(
          collector,
          intents,
          packetIndex,
          bodyOff + 64,
          bodyLen - 64,
          'portmapper-dump',
          'portmapper',
        )
      }
    },
  })

  if (!result) return null
  return {
    coverage: [
      ...result.coverage,
      { protocol: 'portmapper', offset, length, status: 'covered' as const },
    ],
    issues: result.issues,
  }
}
