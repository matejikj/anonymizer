/**
 * IPv6 decoder — traverses extension header chain with bounded depth.
 */

import type { DecodeContext, DecodedNode, DecodedField, EntityCollector, ProtocolModule } from '../types';
import { IPV6_EXT_HOP, IPV6_EXT_ROUTING, IPV6_EXT_FRAGMENT, IPV6_EXT_DEST, IPV6_EXT_AUTH, IPV6_EXT_NONE } from '../types';
import { decodeIpProto } from '../registry';

const MAX_EXT_HEADERS = 16;

const EXT_HEADER_SET = new Set([IPV6_EXT_HOP, IPV6_EXT_ROUTING, IPV6_EXT_FRAGMENT, IPV6_EXT_DEST, IPV6_EXT_AUTH]);

export const ipv6Module: ProtocolModule = {
  id: 'ipv6',

  probe(data: Uint8Array): boolean {
    if (data.length < 40) return false;
    return (data[0]! >> 4) === 6;
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const fields: DecodedField[] = [];
    const children: DecodedNode[] = [];
    const issues: string[] = [];
    const bo = ctx.baseOffset;

    const payloadLength = (data[4]! << 8) | data[5]!;
    let nextHeader = data[6]!;
    const hopLimit = data[7]!;
    const srcIp = data.slice(8, 24);
    const dstIp = data.slice(24, 40);

    fields.push(
      { name: 'version', range: { start: bo, end: bo + 1 }, value: 6 },
      { name: 'payloadLength', range: { start: bo + 4, end: bo + 6 }, value: payloadLength },
      { name: 'nextHeader', range: { start: bo + 6, end: bo + 7 }, value: nextHeader },
      { name: 'hopLimit', range: { start: bo + 7, end: bo + 8 }, value: hopLimit },
      { name: 'src', range: { start: bo + 8, end: bo + 24 }, value: srcIp, display: formatIp6(srcIp) },
      { name: 'dst', range: { start: bo + 24, end: bo + 40 }, value: dstIp, display: formatIp6(dstIp) },
    );

    // Traverse extension headers
    let offset = 40;
    let extCount = 0;
    let isFragment = false;

    while (EXT_HEADER_SET.has(nextHeader) && extCount < MAX_EXT_HEADERS && offset < data.length) {
      if (nextHeader === IPV6_EXT_FRAGMENT) {
        // Fragment header is fixed 8 bytes
        if (offset + 8 > data.length) break;
        const fragNextHeader = data[offset]!;
        const fragOffset = ((data[offset + 2]! << 8) | data[offset + 3]!) >> 3;
        const mf = !!(data[offset + 3]! & 1);
        fields.push({
          name: `ext_fragment`,
          range: { start: bo + offset, end: bo + offset + 8 },
          value: fragOffset,
          display: `Fragment offset=${fragOffset * 8} MF=${mf ? 1 : 0}`,
        });
        isFragment = mf || fragOffset > 0;
        nextHeader = fragNextHeader;
        offset += 8;
      } else if (nextHeader === IPV6_EXT_AUTH) {
        // AH: length in 32-bit words minus 2
        if (offset + 2 > data.length) break;
        const ahNextHeader = data[offset]!;
        const ahLen = (data[offset + 1]! + 2) * 4;
        fields.push({ name: `ext_ah`, range: { start: bo + offset, end: bo + offset + ahLen }, value: ahLen });
        nextHeader = ahNextHeader;
        offset += ahLen;
      } else {
        // Generic extension header: next(1) + len(1) + (len+1)*8 total
        if (offset + 2 > data.length) break;
        const extNext = data[offset]!;
        const extLen = (data[offset + 1]! + 1) * 8;
        fields.push({ name: `ext_${nextHeader}`, range: { start: bo + offset, end: bo + offset + extLen }, value: extLen });
        nextHeader = extNext;
        offset += extLen;
      }
      extCount++;
    }

    if (nextHeader === IPV6_EXT_NONE) {
      // No upper layer
    } else if (isFragment) {
      issues.push('fragment');
    } else if (offset < data.length) {
      const payload = data.subarray(offset, Math.min(offset + payloadLength, data.length));
      const childCtx: DecodeContext = {
        depthBudget: ctx.depthBudget - 1,
        baseOffset: bo + offset,
        hint: nextHeader,
      };
      const child = decodeIpProto(payload, nextHeader, childCtx);
      if (child) children.push(child);
      else issues.push(`unsupported-ipproto:${nextHeader}`);
    }

    return {
      protocolId: 'ipv6',
      range: { start: bo, end: bo + Math.min(40 + payloadLength, data.length) },
      fields,
      children,
      issues,
    };
  },

  collect(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
    for (const f of node.fields) {
      if ((f.name === 'src' || f.name === 'dst') && f.value instanceof Uint8Array && (f.value as Uint8Array).length === 16) {
        out.addIpv6(f.value as Uint8Array, packetNumber);
      }
    }
  },
};

function formatIp6(b: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((b[i]! << 8) | b[i + 1]!).toString(16));
  }
  return groups.join(':');
}
