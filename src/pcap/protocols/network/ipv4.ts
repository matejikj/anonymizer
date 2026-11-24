/**
 * IPv4 decoder — handles options, fragment detection, dispatches to transport.
 */

import type { DecodeContext, DecodedNode, DecodedField, EntityCollector, ProtocolModule } from '../types';
import { decodeIpProto } from '../registry';

export const ipv4Module: ProtocolModule = {
  id: 'ipv4',

  probe(data: Uint8Array): boolean {
    if (data.length < 20) return false;
    return (data[0]! >> 4) === 4;
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const fields: DecodedField[] = [];
    const children: DecodedNode[] = [];
    const issues: string[] = [];
    const bo = ctx.baseOffset;

    const versionIhl = data[0]!;
    const ihl = (versionIhl & 0x0f) * 4;
    const totalLength = (data[2]! << 8) | data[3]!;
    const identification = (data[4]! << 8) | data[5]!;
    const flagsFragment = (data[6]! << 8) | data[7]!;
    const mf = !!(flagsFragment & 0x2000);
    const fragmentOffset = (flagsFragment & 0x1fff) * 8;
    const ttl = data[8]!;
    const protocol = data[9]!;
    const headerChecksum = (data[10]! << 8) | data[11]!;
    const srcIp = data.slice(12, 16);
    const dstIp = data.slice(16, 20);

    fields.push(
      { name: 'version', range: { start: bo, end: bo + 1 }, value: 4 },
      { name: 'ihl', range: { start: bo, end: bo + 1 }, value: ihl },
      { name: 'totalLength', range: { start: bo + 2, end: bo + 4 }, value: totalLength },
      { name: 'identification', range: { start: bo + 4, end: bo + 6 }, value: identification },
      { name: 'flags', range: { start: bo + 6, end: bo + 8 }, value: flagsFragment >> 13, display: `MF=${mf ? 1 : 0} offset=${fragmentOffset}` },
      { name: 'fragmentOffset', range: { start: bo + 6, end: bo + 8 }, value: fragmentOffset },
      { name: 'ttl', range: { start: bo + 8, end: bo + 9 }, value: ttl },
      { name: 'protocol', range: { start: bo + 9, end: bo + 10 }, value: protocol },
      { name: 'headerChecksum', range: { start: bo + 10, end: bo + 12 }, value: headerChecksum },
      { name: 'src', range: { start: bo + 12, end: bo + 16 }, value: srcIp, display: formatIp4(srcIp) },
      { name: 'dst', range: { start: bo + 16, end: bo + 20 }, value: dstIp, display: formatIp4(dstIp) },
    );

    // Options
    if (ihl > 20 && data.length >= ihl) {
      fields.push({ name: 'options', range: { start: bo + 20, end: bo + ihl }, value: data.slice(20, ihl) });
    }

    // Fragment detection
    const isFragment = mf || fragmentOffset > 0;
    if (isFragment) {
      issues.push('fragment');
    }

    // Decode payload (only if not a non-first fragment)
    const payloadStart = Math.min(ihl, data.length);
    const payloadEnd = Math.min(totalLength, data.length);
    if (!isFragment || fragmentOffset === 0) {
      if (payloadStart < payloadEnd) {
        const payload = data.subarray(payloadStart, payloadEnd);
        const childCtx: DecodeContext = {
          depthBudget: ctx.depthBudget - 1,
          baseOffset: bo + payloadStart,
          hint: protocol,
        };
        const child = decodeIpProto(payload, protocol, childCtx);
        if (child) children.push(child);
        else if (!isFragment) issues.push(`unsupported-ipproto:${protocol}`);
      }
    }

    return {
      protocolId: 'ipv4',
      range: { start: bo, end: bo + Math.min(totalLength, data.length) },
      fields,
      children,
      issues,
    };
  },

  collect(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
    for (const f of node.fields) {
      if ((f.name === 'src' || f.name === 'dst') && f.value instanceof Uint8Array) {
        out.addIpv4(f.value, packetNumber);
      }
    }
  },
};

function formatIp4(b: Uint8Array): string {
  return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
}
