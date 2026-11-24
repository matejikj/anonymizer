/**
 * Linux Cooked Capture (SLL and SLL2) decoders.
 */

import type { DecodeContext, DecodedNode, DecodedField, EntityCollector, ProtocolModule } from '../types';
import { decodeEtherType } from '../registry';

/** Linux SLL (link type 113) — 16 byte header */
export const sllModule: ProtocolModule = {
  id: 'sll',

  probe(data: Uint8Array): boolean {
    return data.length >= 16;
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const fields: DecodedField[] = [];
    const children: DecodedNode[] = [];
    const issues: string[] = [];

    const packetType = (data[0]! << 8) | data[1]!;
    const addrType = (data[2]! << 8) | data[3]!;
    const addrLen = (data[4]! << 8) | data[5]!;
    const addr = data.slice(6, 6 + Math.min(addrLen, 8));
    const protocol = (data[14]! << 8) | data[15]!;

    fields.push(
      { name: 'packetType', range: { start: ctx.baseOffset, end: ctx.baseOffset + 2 }, value: packetType },
      { name: 'addrType', range: { start: ctx.baseOffset + 2, end: ctx.baseOffset + 4 }, value: addrType },
      { name: 'addr', range: { start: ctx.baseOffset + 6, end: ctx.baseOffset + 6 + Math.min(addrLen, 8) }, value: addr },
      { name: 'protocol', range: { start: ctx.baseOffset + 14, end: ctx.baseOffset + 16 }, value: protocol, display: `0x${protocol.toString(16).padStart(4, '0')}` },
    );

    if (data.length > 16) {
      const payload = data.subarray(16);
      const childCtx: DecodeContext = { depthBudget: ctx.depthBudget, baseOffset: ctx.baseOffset + 16, hint: protocol };
      const child = decodeEtherType(payload, protocol, childCtx);
      if (child) children.push(child);
      else issues.push(`unsupported-ethertype:0x${protocol.toString(16)}`);
    }

    return { protocolId: 'sll', range: { start: ctx.baseOffset, end: ctx.baseOffset + 16 }, fields, children, issues };
  },

  collect(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
    for (const f of node.fields) {
      if (f.name === 'addr' && (f.value as Uint8Array).length === 6) {
        out.addMac(f.value as Uint8Array, packetNumber);
      }
    }
  },
};

/** Linux SLL2 (link type 276) — 20 byte header */
export const sll2Module: ProtocolModule = {
  id: 'sll2',

  probe(data: Uint8Array): boolean {
    return data.length >= 20;
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const fields: DecodedField[] = [];
    const children: DecodedNode[] = [];
    const issues: string[] = [];

    const protocol = (data[0]! << 8) | data[1]!;
    const addrType = (data[4]! << 8) | data[5]!;
    const addrLen = data[10]!;
    const addr = data.slice(12, 12 + Math.min(addrLen!, 8));

    fields.push(
      { name: 'protocol', range: { start: ctx.baseOffset, end: ctx.baseOffset + 2 }, value: protocol, display: `0x${protocol.toString(16).padStart(4, '0')}` },
      { name: 'addrType', range: { start: ctx.baseOffset + 4, end: ctx.baseOffset + 6 }, value: addrType },
      { name: 'addr', range: { start: ctx.baseOffset + 12, end: ctx.baseOffset + 12 + Math.min(addrLen!, 8) }, value: addr },
    );

    if (data.length > 20) {
      const payload = data.subarray(20);
      const childCtx: DecodeContext = { depthBudget: ctx.depthBudget, baseOffset: ctx.baseOffset + 20, hint: protocol };
      const child = decodeEtherType(payload, protocol, childCtx);
      if (child) children.push(child);
      else issues.push(`unsupported-ethertype:0x${protocol.toString(16)}`);
    }

    return { protocolId: 'sll2', range: { start: ctx.baseOffset, end: ctx.baseOffset + 20 }, fields, children, issues };
  },

  collect(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
    for (const f of node.fields) {
      if (f.name === 'addr' && (f.value as Uint8Array).length === 6) {
        out.addMac(f.value as Uint8Array, packetNumber);
      }
    }
  },
};
