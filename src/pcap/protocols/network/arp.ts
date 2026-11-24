/**
 * ARP decoder (Ethernet/IPv4 only for now).
 */

import type { DecodeContext, DecodedNode, DecodedField, EntityCollector, ProtocolModule } from '../types';

export const arpModule: ProtocolModule = {
  id: 'arp',

  probe(data: Uint8Array): boolean {
    return data.length >= 28; // minimum for Ethernet/IPv4 ARP
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const fields: DecodedField[] = [];
    const issues: string[] = [];
    const bo = ctx.baseOffset;

    const hwType = (data[0]! << 8) | data[1]!;
    const protoType = (data[2]! << 8) | data[3]!;
    const hwLen = data[4]!;
    const protoLen = data[5]!;
    const opcode = (data[6]! << 8) | data[7]!;

    fields.push(
      { name: 'hwType', range: { start: bo, end: bo + 2 }, value: hwType },
      { name: 'protoType', range: { start: bo + 2, end: bo + 4 }, value: protoType },
      { name: 'opcode', range: { start: bo + 6, end: bo + 8 }, value: opcode, display: opcode === 1 ? 'Request' : opcode === 2 ? 'Reply' : `${opcode}` },
    );

    // Ethernet/IPv4 specific (hwLen=6, protoLen=4)
    if (hwLen === 6 && protoLen === 4 && data.length >= 28) {
      const senderMac = data.slice(8, 14);
      const senderIp = data.slice(14, 18);
      const targetMac = data.slice(18, 24);
      const targetIp = data.slice(24, 28);

      fields.push(
        { name: 'senderMac', range: { start: bo + 8, end: bo + 14 }, value: senderMac },
        { name: 'senderIp', range: { start: bo + 14, end: bo + 18 }, value: senderIp, display: formatIp4(senderIp) },
        { name: 'targetMac', range: { start: bo + 18, end: bo + 24 }, value: targetMac },
        { name: 'targetIp', range: { start: bo + 24, end: bo + 28 }, value: targetIp, display: formatIp4(targetIp) },
      );
    } else {
      issues.push(`unsupported-arp-hwtype:${hwLen}/${protoLen}`);
    }

    const totalLen = 8 + hwLen * 2 + protoLen * 2;
    return {
      protocolId: 'arp',
      range: { start: bo, end: bo + Math.min(totalLen, data.length) },
      fields,
      children: [],
      issues,
    };
  },

  collect(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
    for (const f of node.fields) {
      if ((f.name === 'senderIp' || f.name === 'targetIp') && f.value instanceof Uint8Array) {
        out.addIpv4(f.value, packetNumber);
      }
      if ((f.name === 'senderMac' || f.name === 'targetMac') && f.value instanceof Uint8Array) {
        out.addMac(f.value, packetNumber);
      }
    }
  },
};

function formatIp4(b: Uint8Array): string {
  return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
}
