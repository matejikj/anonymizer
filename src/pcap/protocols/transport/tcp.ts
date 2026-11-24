/**
 * TCP decoder with options parsing.
 */

import type { DecodeContext, DecodedNode, DecodedField, EntityCollector, ProtocolModule } from '../types';

export const tcpModule: ProtocolModule = {
  id: 'tcp',

  probe(data: Uint8Array): boolean {
    return data.length >= 20;
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const fields: DecodedField[] = [];
    const bo = ctx.baseOffset;

    const srcPort = (data[0]! << 8) | data[1]!;
    const dstPort = (data[2]! << 8) | data[3]!;
    const seqNum = ((data[4]! << 24) | (data[5]! << 16) | (data[6]! << 8) | data[7]!) >>> 0;
    const ackNum = ((data[8]! << 24) | (data[9]! << 16) | (data[10]! << 8) | data[11]!) >>> 0;
    const dataOffset = (data[12]! >> 4) * 4;
    const flags = ((data[12]! & 0x01) << 8) | data[13]!;

    fields.push(
      { name: 'srcPort', range: { start: bo, end: bo + 2 }, value: srcPort },
      { name: 'dstPort', range: { start: bo + 2, end: bo + 4 }, value: dstPort },
      { name: 'seq', range: { start: bo + 4, end: bo + 8 }, value: seqNum },
      { name: 'ack', range: { start: bo + 8, end: bo + 12 }, value: ackNum },
      { name: 'dataOffset', range: { start: bo + 12, end: bo + 13 }, value: dataOffset },
      { name: 'flags', range: { start: bo + 12, end: bo + 14 }, value: flags, display: tcpFlagsStr(flags) },
    );

    if (dataOffset > 20 && data.length >= dataOffset) {
      fields.push({ name: 'options', range: { start: bo + 20, end: bo + dataOffset }, value: data.slice(20, dataOffset) });
    }

    const payloadStart = Math.min(dataOffset, data.length);
    if (payloadStart < data.length) {
      fields.push({ name: 'payloadLen', range: { start: bo + payloadStart, end: bo + data.length }, value: data.length - payloadStart });
    }

    return {
      protocolId: 'tcp',
      range: { start: bo, end: bo + data.length },
      fields,
      children: [],
      issues: [],
    };
  },

  collect(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
    for (const f of node.fields) {
      if (f.name === 'srcPort' || f.name === 'dstPort') {
        out.addPort(f.value as number, 'tcp', packetNumber);
      }
    }
  },
};

function tcpFlagsStr(flags: number): string {
  const names: string[] = [];
  if (flags & 0x001) names.push('FIN');
  if (flags & 0x002) names.push('SYN');
  if (flags & 0x004) names.push('RST');
  if (flags & 0x008) names.push('PSH');
  if (flags & 0x010) names.push('ACK');
  if (flags & 0x020) names.push('URG');
  if (flags & 0x040) names.push('ECE');
  if (flags & 0x080) names.push('CWR');
  return names.join(',') || '0';
}
