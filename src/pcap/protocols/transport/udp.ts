/**
 * UDP decoder.
 */

import type { DecodeContext, DecodedNode, DecodedField, EntityCollector, ProtocolModule } from '../types';
import { decodeUdpPort } from '../registry';

export const udpModule: ProtocolModule = {
  id: 'udp',

  probe(data: Uint8Array): boolean {
    return data.length >= 8;
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const fields: DecodedField[] = [];
    const children: DecodedNode[] = [];
    const bo = ctx.baseOffset;

    const srcPort = (data[0]! << 8) | data[1]!;
    const dstPort = (data[2]! << 8) | data[3]!;
    const length = (data[4]! << 8) | data[5]!;
    const checksum = (data[6]! << 8) | data[7]!;

    fields.push(
      { name: 'srcPort', range: { start: bo, end: bo + 2 }, value: srcPort },
      { name: 'dstPort', range: { start: bo + 2, end: bo + 4 }, value: dstPort },
      { name: 'length', range: { start: bo + 4, end: bo + 6 }, value: length },
      { name: 'checksum', range: { start: bo + 6, end: bo + 8 }, value: checksum },
    );

    if (data.length > 8) {
      fields.push({ name: 'payloadLen', range: { start: bo + 8, end: bo + data.length }, value: data.length - 8 });

      // Application-layer tunnels keyed by UDP destination port (e.g. VXLAN/4789).
      const payload = data.subarray(8, Math.min(length, data.length));
      if (payload.length > 0) {
        const childCtx: DecodeContext = { depthBudget: ctx.depthBudget, baseOffset: bo + 8, hint: dstPort };
        const child = decodeUdpPort(payload, dstPort, childCtx);
        if (child) children.push(child);
      }
    }

    return {
      protocolId: 'udp',
      range: { start: bo, end: bo + Math.min(length, data.length) },
      fields,
      children,
      issues: [],
    };
  },

  collect(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
    for (const f of node.fields) {
      if (f.name === 'srcPort' || f.name === 'dstPort') {
        out.addPort(f.value as number, 'udp', packetNumber);
      }
    }
  },
};
