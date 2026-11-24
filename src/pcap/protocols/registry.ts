/**
 * Protocol registry — dispatches decode based on link type, EtherType, or IP protocol.
 */

import type { DecodeContext, DecodedNode, ProtocolModule } from './types';
import { MAX_DECODE_DEPTH } from './types';

const linkModules: Map<number, ProtocolModule> = new Map();
const etherTypeModules: Map<number, ProtocolModule> = new Map();
const ipProtoModules: Map<number, ProtocolModule> = new Map();
/** Keyed by UDP destination port — for tunnels like VXLAN that aren't an IP-proto number. */
const udpPortModules: Map<number, ProtocolModule> = new Map();

export function registerLinkModule(linkType: number, mod: ProtocolModule): void {
  linkModules.set(linkType, mod);
}

export function registerEtherTypeModule(etherType: number, mod: ProtocolModule): void {
  etherTypeModules.set(etherType, mod);
}

export function registerIpProtoModule(proto: number, mod: ProtocolModule): void {
  ipProtoModules.set(proto, mod);
}

export function registerUdpPortModule(port: number, mod: ProtocolModule): void {
  udpPortModules.set(port, mod);
}

export function decodeLink(data: Uint8Array, linkType: number): DecodedNode | null {
  const mod = linkModules.get(linkType);
  if (!mod) return null;
  const ctx: DecodeContext = { depthBudget: MAX_DECODE_DEPTH, baseOffset: 0, hint: linkType };
  if (!mod.probe(data, ctx)) return null;
  return mod.decode(data, ctx);
}

export function decodeEtherType(data: Uint8Array, etherType: number, ctx: DecodeContext): DecodedNode | null {
  if (ctx.depthBudget <= 0) return null;
  const mod = etherTypeModules.get(etherType);
  if (!mod) return null;
  if (!mod.probe(data, ctx)) return null;
  return mod.decode(data, ctx);
}

export function decodeIpProto(data: Uint8Array, proto: number, ctx: DecodeContext): DecodedNode | null {
  if (ctx.depthBudget <= 0) return null;
  const mod = ipProtoModules.get(proto);
  if (!mod) return null;
  if (!mod.probe(data, ctx)) return null;
  return mod.decode(data, ctx);
}

export function decodeUdpPort(data: Uint8Array, port: number, ctx: DecodeContext): DecodedNode | null {
  if (ctx.depthBudget <= 0) return null;
  const mod = udpPortModules.get(port);
  if (!mod) return null;
  if (!mod.probe(data, ctx)) return null;
  return mod.decode(data, ctx);
}

export function getLinkModule(linkType: number): ProtocolModule | undefined {
  return linkModules.get(linkType);
}

export function getEtherTypeModule(etherType: number): ProtocolModule | undefined {
  return etherTypeModules.get(etherType);
}

export function getIpProtoModule(proto: number): ProtocolModule | undefined {
  return ipProtoModules.get(proto);
}

export function getUdpPortModule(port: number): ProtocolModule | undefined {
  return udpPortModules.get(port);
}
