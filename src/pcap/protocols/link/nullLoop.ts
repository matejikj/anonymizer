/**
 * DLT_NULL (0) / DLT_LOOP (108) — 4-byte AF family then IP.
 */

import type { DecodeContext, DecodedNode, EntityCollector, ProtocolModule } from '../types'
import { ETHERTYPE_IPV4, ETHERTYPE_IPV6 } from '../types'
import { decodeEtherType } from '../registry'

function decodeNullLoop(data: Uint8Array, ctx: DecodeContext): DecodedNode {
  const bo = ctx.baseOffset
  if (data.length < 5) {
    return {
      protocolId: 'null-loop',
      range: { start: bo, end: bo + data.length },
      fields: [],
      children: [],
      issues: ['null-loop-trunc'],
    }
  }
  const le = data[0]! | (data[1]! << 8) | (data[2]! << 16) | (data[3]! << 24)
  const be = (data[0]! << 24) | (data[1]! << 16) | (data[2]! << 8) | data[3]!
  const ver = data[4]! >> 4
  let ether = 0
  for (const af of [le, be]) {
    if (af === 2 && ver === 4) {
      ether = ETHERTYPE_IPV4
      break
    }
    if ((af === 24 || af === 28 || af === 30) && ver === 6) {
      ether = ETHERTYPE_IPV6
      break
    }
  }
  const childCtx: DecodeContext = { depthBudget: ctx.depthBudget, baseOffset: bo + 4, hint: ether }
  const child = ether ? decodeEtherType(data.subarray(4), ether, childCtx) : null
  return {
    protocolId: 'null-loop',
    range: { start: bo, end: bo + data.length },
    fields: [{ name: 'af', range: { start: bo, end: bo + 4 }, value: le }],
    children: child ? [child] : [],
    issues: child ? [] : ['unsupported-payload'],
  }
}

export const nullLinkModule: ProtocolModule = {
  id: 'null',
  probe: (d) => d.length >= 4,
  decode: decodeNullLoop,
  collect() {},
}

export const loopLinkModule: ProtocolModule = {
  id: 'loop',
  probe: (d) => d.length >= 4,
  decode: decodeNullLoop,
  collect(_n: DecodedNode, _o: EntityCollector, _p: number) {},
}
