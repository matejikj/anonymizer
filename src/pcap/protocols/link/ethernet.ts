/**
 * Ethernet II decoder with VLAN/QinQ tag traversal.
 */

import type { DecodeContext, DecodedNode, DecodedField, EntityCollector, ProtocolModule } from '../types';
import { ETHERTYPE_VLAN, ETHERTYPE_QINQ } from '../types';
import { decodeEtherType } from '../registry';

export const ethernetModule: ProtocolModule = {
  id: 'ethernet',

  probe(data: Uint8Array, _ctx: DecodeContext): boolean {
    return data.length >= 14;
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const fields: DecodedField[] = [];
    const children: DecodedNode[] = [];
    const issues: string[] = [];

    const dstMac = data.slice(0, 6);
    const srcMac = data.slice(6, 12);
    let etherType = (data[12]! << 8) | data[13]!;
    let headerLen = 14;

    fields.push(
      { name: 'dst', range: { start: ctx.baseOffset, end: ctx.baseOffset + 6 }, value: dstMac, display: formatMac(dstMac) },
      { name: 'src', range: { start: ctx.baseOffset + 6, end: ctx.baseOffset + 12 }, value: srcMac, display: formatMac(srcMac) },
    );

    // Traverse VLAN tags (802.1Q and QinQ)
    let vlanCount = 0;
    while ((etherType === ETHERTYPE_VLAN || etherType === ETHERTYPE_QINQ) && headerLen + 4 <= data.length && vlanCount < 4) {
      const tci = (data[headerLen]! << 8) | data[headerLen + 1]!;
      const vlanId = tci & 0x0fff;
      fields.push({
        name: `vlan${vlanCount}`,
        range: { start: ctx.baseOffset + headerLen, end: ctx.baseOffset + headerLen + 4 },
        value: vlanId,
        display: `VLAN ${vlanId}`,
      });
      etherType = (data[headerLen + 2]! << 8) | data[headerLen + 3]!;
      headerLen += 4;
      vlanCount++;
    }

    fields.push({
      name: 'etherType',
      range: { start: ctx.baseOffset + headerLen - 2, end: ctx.baseOffset + headerLen },
      value: etherType,
      display: `0x${etherType.toString(16).padStart(4, '0')}`,
    });

    // Decode payload by EtherType
    if (headerLen < data.length) {
      const payload = data.subarray(headerLen);
      const childCtx: DecodeContext = {
        depthBudget: ctx.depthBudget,
        baseOffset: ctx.baseOffset + headerLen,
        hint: etherType,
      };
      const child = decodeEtherType(payload, etherType, childCtx);
      if (child) {
        children.push(child);
      } else {
        issues.push(`unsupported-ethertype:0x${etherType.toString(16)}`);
      }
    }

    return {
      protocolId: 'ethernet',
      range: { start: ctx.baseOffset, end: ctx.baseOffset + headerLen },
      fields,
      children,
      issues,
    };
  },

  collect(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
    for (const f of node.fields) {
      if (f.name === 'dst' || f.name === 'src') {
        out.addMac(f.value as Uint8Array, packetNumber);
      } else if (f.name.startsWith('vlan')) {
        out.addVlan(f.value as number, packetNumber);
      }
    }
  },
};

function formatMac(mac: Uint8Array): string {
  return Array.from(mac).map(b => b.toString(16).padStart(2, '0')).join(':');
}
