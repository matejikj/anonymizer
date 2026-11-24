/**
 * Raw IP link types (228 = Raw IPv4, 229 = Raw IPv6).
 * No link-layer header — directly dispatches to network layer.
 */

import type { DecodeContext, DecodedNode, EntityCollector, ProtocolModule } from '../types';
import { ETHERTYPE_IPV4, ETHERTYPE_IPV6 } from '../types';
import { decodeEtherType } from '../registry';

export const rawIpv4Module: ProtocolModule = {
  id: 'raw-ipv4',
  probe(data: Uint8Array): boolean { return data.length >= 20; },
  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const child = decodeEtherType(data, ETHERTYPE_IPV4, ctx);
    return {
      protocolId: 'raw-ipv4',
      range: { start: ctx.baseOffset, end: ctx.baseOffset },
      fields: [],
      children: child ? [child] : [],
      issues: child ? [] : ['unsupported-payload'],
    };
  },
  collect(_node: DecodedNode, _out: EntityCollector, _pkt: number): void {},
};

export const rawIpv6Module: ProtocolModule = {
  id: 'raw-ipv6',
  probe(data: Uint8Array): boolean { return data.length >= 40; },
  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
    const child = decodeEtherType(data, ETHERTYPE_IPV6, ctx);
    return {
      protocolId: 'raw-ipv6',
      range: { start: ctx.baseOffset, end: ctx.baseOffset },
      fields: [],
      children: child ? [child] : [],
      issues: child ? [] : ['unsupported-payload'],
    };
  },
  collect(_node: DecodedNode, _out: EntityCollector, _pkt: number): void {},
};
