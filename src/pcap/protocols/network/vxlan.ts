/**
 * VXLAN decoder — UDP-encapsulated Ethernet tunnel (destination port 4789).
 *
 * Registered via registerUdpPortModule, not registerIpProtoModule — VXLAN is keyed by
 * UDP destination port, not an IP protocol number. Scope matches sanitize/tunnel.ts's
 * sanitizeVxlan exactly: inner Ethernet MACs plus inner IPv4/IPv6 addresses only, no
 * inner transport (see tunnel.ts for the rationale).
 */

import type { DecodeContext, DecodedNode, DecodedField, EntityCollector, ProtocolModule } from '../types';
import { decodeIpInIpNode, decodeIpv6InIpNode } from './tunnel';

export const VXLAN_UDP_PORT = 4789;

export const vxlanModule: ProtocolModule = {
  id: 'vxlan',

  probe(data: Uint8Array): boolean {
    return data.length >= 8;
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const bo = ctx.baseOffset;
    if (data.length < 8) {
      return { protocolId: 'vxlan', range: { start: bo, end: bo + data.length }, fields: [], children: [], issues: ['malformed-tunnel'] };
    }

    const flags = data[0]!;
    const vni = (data[4]! << 16) | (data[5]! << 8) | data[6]!;
    const fields: DecodedField[] = [
      { name: 'flags', range: { start: bo, end: bo + 1 }, value: flags },
      { name: 'vni', range: { start: bo + 4, end: bo + 7 }, value: vni },
    ];

    const children: DecodedNode[] = [];
    const issues: string[] = [];

    if (ctx.depthBudget <= 0) {
      issues.push('unsupported-ipproto:vxlan');
      return { protocolId: 'vxlan', range: { start: bo, end: bo + data.length }, fields, children, issues };
    }

    const inner = data.subarray(8);
    if (inner.length >= 14) {
      const dstMac = inner.slice(0, 6);
      const srcMac = inner.slice(6, 12);
      const etherType = (inner[12]! << 8) | inner[13]!;
      fields.push(
        { name: 'innerDstMac', range: { start: bo + 8, end: bo + 14 }, value: dstMac },
        { name: 'innerSrcMac', range: { start: bo + 14, end: bo + 20 }, value: srcMac },
      );

      const payload = inner.subarray(14);
      const childCtx: DecodeContext = { depthBudget: ctx.depthBudget - 1, baseOffset: bo + 20, hint: etherType };
      if (payload.length >= 20 && etherType === 0x0800) {
        children.push(decodeIpInIpNode(payload, childCtx));
      } else if (payload.length >= 40 && etherType === 0x86dd) {
        children.push(decodeIpv6InIpNode(payload, childCtx));
      } else if (payload.length > 0) {
        issues.push(`unsupported-tunnel-transport:vxlan-ethertype-0x${etherType.toString(16)}`);
      }
    } else if (inner.length > 0) {
      issues.push('malformed-tunnel');
    }

    return { protocolId: 'vxlan', range: { start: bo, end: bo + data.length }, fields, children, issues };
  },

  collect(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
    for (const f of node.fields) {
      if ((f.name === 'innerDstMac' || f.name === 'innerSrcMac') && f.value instanceof Uint8Array) {
        out.addMac(f.value, packetNumber);
      }
    }
  },
};
