import type { FlowEndpoint } from './types';

/** Direction-normalized conversation key — UI / dialog correlation only (CF-04). */
export function conversationKeyFromEndpoint(ep: FlowEndpoint): string {
  const a = `${ep.srcIp}:${ep.srcPort}`;
  const b = `${ep.dstIp}:${ep.dstPort}`;
  const [left, right] = a <= b ? [a, b] : [b, a];
  return `${ep.ipProto}:${left}<->${right}`;
}

/**
 * Directional TCP stream key — exact 4-tuple for reassembly (CF-04).
 * Request and response never share a sequence space.
 */
export function directionalStreamKey(ep: FlowEndpoint, generation = 0): string {
  return `${ep.ipProto}:${ep.srcIp}:${ep.srcPort}->${ep.dstIp}:${ep.dstPort}#${generation}`;
}

/** @deprecated use conversationKeyFromEndpoint — kept for callers that only need UI correlation */
export function flowKeyFromEndpoint(ep: FlowEndpoint): string {
  return conversationKeyFromEndpoint(ep);
}

export function ipv4FragmentKey(
  srcIp: string,
  dstIp: string,
  ipProto: number,
  identification: number,
  interfaceId = 0,
  sectionIndex = 0,
): string {
  return `frag4:${interfaceId}:${sectionIndex}:${srcIp}:${dstIp}:${ipProto}:${identification}`;
}

export function ipv6FragmentKey(
  srcIp: string,
  dstIp: string,
  nextHeader: number,
  identification: number,
  interfaceId = 0,
  sectionIndex = 0,
): string {
  return `frag6:${interfaceId}:${sectionIndex}:${srcIp}:${dstIp}:${nextHeader}:${identification}`;
}
