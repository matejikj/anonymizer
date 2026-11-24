/**
 * ICMPv4 and ICMPv6 decoders.
 */

import type { DecodeContext, DecodedNode, DecodedField, EntityCollector, ProtocolModule } from '../types';

export const icmpv4Module: ProtocolModule = {
  id: 'icmpv4',

  probe(data: Uint8Array): boolean {
    return data.length >= 8;
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const fields: DecodedField[] = [];
    const bo = ctx.baseOffset;

    const type = data[0]!;
    const code = data[1]!;
    const checksum = (data[2]! << 8) | data[3]!;

    fields.push(
      { name: 'type', range: { start: bo, end: bo + 1 }, value: type, display: icmpv4TypeName(type) },
      { name: 'code', range: { start: bo + 1, end: bo + 2 }, value: code },
      { name: 'checksum', range: { start: bo + 2, end: bo + 4 }, value: checksum },
    );

    // For error messages (type 3,4,5,11,12), bytes 8+ contain original IP header
    if ((type === 3 || type === 4 || type === 5 || type === 11 || type === 12) && data.length > 8) {
      fields.push({ name: 'embeddedHeader', range: { start: bo + 8, end: bo + Math.min(data.length, 8 + 28) }, value: data.slice(8, Math.min(data.length, 8 + 28)) });
    }

    return {
      protocolId: 'icmpv4',
      range: { start: bo, end: bo + data.length },
      fields,
      children: [],
      issues: [],
    };
  },

  collect(_node: DecodedNode, _out: EntityCollector, _pkt: number): void {},
};

export const icmpv6Module: ProtocolModule = {
  id: 'icmpv6',

  probe(data: Uint8Array): boolean {
    return data.length >= 8;
  },

  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const fields: DecodedField[] = [];
    const bo = ctx.baseOffset;

    const type = data[0]!;
    const code = data[1]!;
    const checksum = (data[2]! << 8) | data[3]!;

    fields.push(
      { name: 'type', range: { start: bo, end: bo + 1 }, value: type, display: icmpv6TypeName(type) },
      { name: 'code', range: { start: bo + 1, end: bo + 2 }, value: code },
      { name: 'checksum', range: { start: bo + 2, end: bo + 4 }, value: checksum },
    );

    // Error messages (type 1-4) contain original packet
    if (type >= 1 && type <= 4 && data.length > 8) {
      fields.push({ name: 'embeddedHeader', range: { start: bo + 8, end: bo + Math.min(data.length, 8 + 48) }, value: data.slice(8, Math.min(data.length, 8 + 48)) });
    }

    return {
      protocolId: 'icmpv6',
      range: { start: bo, end: bo + data.length },
      fields,
      children: [],
      issues: [],
    };
  },

  collect(_node: DecodedNode, _out: EntityCollector, _pkt: number): void {},
};

function icmpv4TypeName(type: number): string {
  switch (type) {
    case 0: return 'Echo Reply';
    case 3: return 'Destination Unreachable';
    case 4: return 'Source Quench';
    case 5: return 'Redirect';
    case 8: return 'Echo Request';
    case 11: return 'Time Exceeded';
    case 12: return 'Parameter Problem';
    default: return `Type ${type}`;
  }
}

function icmpv6TypeName(type: number): string {
  switch (type) {
    case 1: return 'Destination Unreachable';
    case 2: return 'Packet Too Big';
    case 3: return 'Time Exceeded';
    case 4: return 'Parameter Problem';
    case 128: return 'Echo Request';
    case 129: return 'Echo Reply';
    case 133: return 'Router Solicitation';
    case 134: return 'Router Advertisement';
    case 135: return 'Neighbor Solicitation';
    case 136: return 'Neighbor Advertisement';
    default: return `Type ${type}`;
  }
}
