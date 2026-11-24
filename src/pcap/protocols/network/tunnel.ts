/**
 * IP-in-IP, IPv6-in-IP, and GRE tunnel decoders (analysis layer).
 *
 * Scope is deliberately restricted to match sanitize/tunnel.ts exactly: only inner IP
 * addresses and further nested tunnel layers (bounded by the same depth budget) are
 * decoded. Inner transport (TCP/UDP/ICMP) is never decoded here — sanitize/tunnel.ts
 * doesn't sanitize it either, so claiming it as "covered" in analysis would overstate
 * what the anonymized export actually protects. An explicit
 * `unsupported-tunnel-transport:<proto>` issue marks that boundary instead of silently
 * stopping.
 */

import type { DecodeContext, DecodedNode, DecodedField, EntityCollector, ProtocolModule } from '../types';
import { IPPROTO_IPV4, IPPROTO_IPV6, IPPROTO_GRE } from '../types';

function isTunnelProto(proto: number): boolean {
  return proto === IPPROTO_IPV4 || proto === IPPROTO_IPV6 || proto === IPPROTO_GRE;
}

function decodeTunnelLayer(data: Uint8Array, protocol: number, ctx: DecodeContext): DecodedNode {
  if (ctx.depthBudget <= 0) {
    return {
      protocolId: `tunnel-proto-${protocol}`,
      range: { start: ctx.baseOffset, end: ctx.baseOffset },
      fields: [],
      children: [],
      issues: [`unsupported-ipproto:${protocol}`],
    };
  }
  switch (protocol) {
    case IPPROTO_IPV4: return decodeIpInIpNode(data, ctx);
    case IPPROTO_IPV6: return decodeIpv6InIpNode(data, ctx);
    case IPPROTO_GRE: return decodeGreNode(data, ctx);
    default:
      return {
        protocolId: `tunnel-proto-${protocol}`,
        range: { start: ctx.baseOffset, end: ctx.baseOffset },
        fields: [],
        children: [],
        issues: [`unsupported-ipproto:${protocol}`],
      };
  }
}

export function decodeIpInIpNode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
  const bo = ctx.baseOffset;
  if (data.length < 20) {
    return { protocolId: 'ipip-ipv4', range: { start: bo, end: bo + data.length }, fields: [], children: [], issues: ['malformed-tunnel'] };
  }
  const ihl = (data[0]! & 0x0f) * 4;
  if (ihl < 20 || ihl > data.length) {
    return { protocolId: 'ipip-ipv4', range: { start: bo, end: bo + data.length }, fields: [], children: [], issues: ['malformed-tunnel'] };
  }

  const nextProto = data[9]!;
  const srcIp = data.slice(12, 16);
  const dstIp = data.slice(16, 20);
  const fields: DecodedField[] = [
    { name: 'protocol', range: { start: bo + 9, end: bo + 10 }, value: nextProto },
    { name: 'src', range: { start: bo + 12, end: bo + 16 }, value: srcIp, display: formatIp4(srcIp) },
    { name: 'dst', range: { start: bo + 16, end: bo + 20 }, value: dstIp, display: formatIp4(dstIp) },
  ];

  const children: DecodedNode[] = [];
  const issues: string[] = [];
  const payload = data.subarray(ihl);
  if (payload.length > 0 && isTunnelProto(nextProto)) {
    children.push(decodeTunnelLayer(payload, nextProto, { depthBudget: ctx.depthBudget - 1, baseOffset: bo + ihl, hint: nextProto }));
  } else if (payload.length > 0) {
    issues.push(`unsupported-tunnel-transport:${nextProto}`);
  }

  return { protocolId: 'ipip-ipv4', range: { start: bo, end: bo + data.length }, fields, children, issues };
}

export function decodeIpv6InIpNode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
  const bo = ctx.baseOffset;
  if (data.length < 40) {
    return { protocolId: 'ipip-ipv6', range: { start: bo, end: bo + data.length }, fields: [], children: [], issues: ['malformed-tunnel'] };
  }

  const nextHeader = data[6]!;
  const srcIp = data.slice(8, 24);
  const dstIp = data.slice(24, 40);
  const fields: DecodedField[] = [
    { name: 'nextHeader', range: { start: bo + 6, end: bo + 7 }, value: nextHeader },
    { name: 'src', range: { start: bo + 8, end: bo + 24 }, value: srcIp, display: formatIp6(srcIp) },
    { name: 'dst', range: { start: bo + 24, end: bo + 40 }, value: dstIp, display: formatIp6(dstIp) },
  ];

  const children: DecodedNode[] = [];
  const issues: string[] = [];
  const payload = data.subarray(40);
  if (payload.length > 0 && isTunnelProto(nextHeader)) {
    children.push(decodeTunnelLayer(payload, nextHeader, { depthBudget: ctx.depthBudget - 1, baseOffset: bo + 40, hint: nextHeader }));
  } else if (payload.length > 0) {
    issues.push(`unsupported-tunnel-transport:${nextHeader}`);
  }

  return { protocolId: 'ipip-ipv6', range: { start: bo, end: bo + data.length }, fields, children, issues };
}

function decodeGreNode(data: Uint8Array, ctx: DecodeContext): DecodedNode {
  const bo = ctx.baseOffset;
  if (data.length < 4) {
    return { protocolId: 'gre', range: { start: bo, end: bo + data.length }, fields: [], children: [], issues: ['malformed-tunnel'] };
  }

  const flags = (data[0]! << 8) | data[1]!;
  const protocol = (data[2]! << 8) | data[3]!;

  let headerSize = 4;
  if (flags & 0x8000) headerSize += 4; // checksum + reserved1
  if (flags & 0x2000) headerSize += 4; // key
  if (flags & 0x1000) headerSize += 4; // sequence

  if (headerSize > data.length) {
    return { protocolId: 'gre', range: { start: bo, end: bo + data.length }, fields: [], children: [], issues: ['malformed-tunnel'] };
  }

  const fields: DecodedField[] = [
    { name: 'flags', range: { start: bo, end: bo + 2 }, value: flags },
    { name: 'protocol', range: { start: bo + 2, end: bo + 4 }, value: protocol },
  ];

  const children: DecodedNode[] = [];
  const issues: string[] = [];
  const payload = data.subarray(headerSize);
  const childCtx: DecodeContext = { depthBudget: ctx.depthBudget - 1, baseOffset: bo + headerSize, hint: protocol };

  // GRE's protocol field is an EtherType (0x0800/0x86dd), not an IP-protocol number.
  if (payload.length >= 20 && protocol === 0x0800) {
    children.push(decodeIpInIpNode(payload, childCtx));
  } else if (payload.length >= 40 && protocol === 0x86dd) {
    children.push(decodeIpv6InIpNode(payload, childCtx));
  } else if (payload.length > 0) {
    issues.push(`unsupported-tunnel-transport:gre-ethertype-0x${protocol.toString(16)}`);
  }

  return { protocolId: 'gre', range: { start: bo, end: bo + data.length }, fields, children, issues };
}

function collectIpv4Node(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
  for (const f of node.fields) {
    if ((f.name === 'src' || f.name === 'dst') && f.value instanceof Uint8Array) out.addIpv4(f.value, packetNumber);
  }
}

function collectIpv6Node(node: DecodedNode, out: EntityCollector, packetNumber: number): void {
  for (const f of node.fields) {
    if ((f.name === 'src' || f.name === 'dst') && f.value instanceof Uint8Array) out.addIpv6(f.value, packetNumber);
  }
}

export const ipInIpModule: ProtocolModule = {
  id: 'ipip-ipv4',
  probe(data: Uint8Array): boolean {
    return data.length >= 20 && (data[0]! >> 4) === 4;
  },
  decode: decodeIpInIpNode,
  collect: collectIpv4Node,
};

export const ipv6InIpModule: ProtocolModule = {
  id: 'ipip-ipv6',
  probe(data: Uint8Array): boolean {
    return data.length >= 40 && (data[0]! >> 4) === 6;
  },
  decode: decodeIpv6InIpNode,
  collect: collectIpv6Node,
};

export const greModule: ProtocolModule = {
  id: 'gre',
  probe(data: Uint8Array): boolean {
    return data.length >= 4;
  },
  decode: decodeGreNode,
  collect(): void {
    // GRE's own header carries no addresses — collected via its decoded children instead.
  },
};

function formatIp4(b: Uint8Array): string {
  return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
}

function formatIp6(b: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((b[i]! << 8) | b[i + 1]!).toString(16));
  return groups.join(':');
}
