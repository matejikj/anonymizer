/**
 * Bounded tunnel recursion (IP-in-IP, GRE, VXLAN) + ICMP embedded + ICMPv6 NDP (CF-13).
 *
 * L3 encapsulation is sanitized here; continuation into L4/application is provided by
 * the engine via `onInnerTransport` so nested SIP/UDP uses the same policy and mapping.
 */

import { PatchCollector } from './PatchCollector';
import type { MappingLike } from '../anonymization/mapping';
import type { IntentCollector } from '../discovery/intentCollector';
import type { LayerCoverage } from './types';
import { patchVlanTci } from './vlanPatch';
import { createProtocolNeutralMaskFill } from './maskFill';

export const MAX_TUNNEL_DEPTH = 4;
const IP_PROTO_IPIP = 4;
const IP_PROTO_IPV6 = 41;
const IP_PROTO_GRE = 47;
const IP_PROTO_TCP = 6;
const IP_PROTO_UDP = 17;
const VXLAN_UDP_PORT = 4789;

/** ICMPv6 NDP message types (RFC 4861). */
const NDP_RS = 133;
const NDP_RA = 134;
const NDP_NS = 135;
const NDP_NA = 136;
const NDP_REDIRECT = 137;

export interface TunnelResult {
  coverage: LayerCoverage[];
  /** True if recursion limit reached. */
  depthExceeded: boolean;
  drop?: boolean;
}

export interface InnerTransportContinue {
  readonly offset: number;
  readonly ipProto: number;
  readonly isIpv6: boolean;
  readonly srcIp: string;
  readonly dstIp: string;
  readonly depth: number;
}

export type InnerTransportHandler = (inner: InnerTransportContinue) => {
  readonly coverage: LayerCoverage[];
  readonly drop?: boolean;
};

export interface TunnelIdentityContext {
  readonly packetIndex: number;
  readonly intents?: IntentCollector;
}

/**
 * Recursively decode and sanitize tunnel encapsulations.
 * When the inner next-header is TCP/UDP/ICMP/…, calls `onInnerTransport` (CF-13).
 */
export function sanitizeTunnel(
  buffer: Uint8Array,
  offset: number,
  length: number,
  protocol: number,
  collector: PatchCollector,
  mapping: MappingLike,
  depth: number = 0,
  onInnerTransport?: InnerTransportHandler,
  identity?: TunnelIdentityContext,
): TunnelResult {
  const coverage: LayerCoverage[] = [];

  if (depth >= MAX_TUNNEL_DEPTH) {
    coverage.push({ protocol: 'tunnel', offset, length, status: 'unsupported' });
    return { coverage, depthExceeded: true };
  }

  switch (protocol) {
    case IP_PROTO_IPIP:
      return decodeInnerIpv4(
        buffer, offset, length, collector, mapping, depth, coverage, onInnerTransport, identity,
      );
    case IP_PROTO_IPV6:
      return decodeInnerIpv6(
        buffer, offset, length, collector, mapping, depth, coverage, onInnerTransport, identity,
      );
    case IP_PROTO_GRE:
      return decodeGre(
        buffer, offset, length, collector, mapping, depth, coverage, onInnerTransport, identity,
      );
    default:
      coverage.push({ protocol: `proto-${protocol}`, offset, length, status: 'unsupported' });
      return { coverage, depthExceeded: false };
  }
}

/**
 * Sanitize ICMP embedded IP header + available transport ports (CF-13).
 * Incomplete transport bytes beyond ports are not marked covered.
 */
export function sanitizeIcmpEmbedded(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  identity?: TunnelIdentityContext,
): LayerCoverage[] {
  const coverage: LayerCoverage[] = [];
  const packetIndex = identity?.packetIndex ?? 0;
  const intents = identity?.intents;

  if (length < 20) {
    coverage.push({ protocol: 'icmp-embedded', offset, length, status: 'malformed' });
    return coverage;
  }

  const version = (buffer[offset]! >> 4) & 0xf;
  if (version === 4) {
    const ihl = (buffer[offset]! & 0xf) * 4;
    if (ihl < 20 || ihl > length) {
      coverage.push({ protocol: 'icmp-embedded-ipv4', offset, length, status: 'malformed' });
      return coverage;
    }

    patchIpv4(buffer, offset + 12, collector, mapping, packetIndex, intents);
    patchIpv4(buffer, offset + 16, collector, mapping, packetIndex, intents);
    coverage.push({ protocol: 'icmp-embedded-ipv4', offset, length: ihl, status: 'covered' });

    const nextProto = buffer[offset + 9]!;
    const transportOff = offset + ihl;
    const transportLen = length - ihl;
    appendEmbeddedTransport(
      buffer,
      transportOff,
      transportLen,
      nextProto,
      collector,
      mapping,
      coverage,
      packetIndex,
      intents,
    );
  } else if (version === 6) {
    if (length < 40) {
      coverage.push({ protocol: 'icmp-embedded-ipv6', offset, length, status: 'malformed' });
      return coverage;
    }

    patchIpv6(buffer, offset + 8, collector, mapping, packetIndex, intents);
    patchIpv6(buffer, offset + 24, collector, mapping, packetIndex, intents);
    coverage.push({ protocol: 'icmp-embedded-ipv6', offset, length: 40, status: 'covered' });

    const nextProto = buffer[offset + 6]!;
    appendEmbeddedTransport(
      buffer,
      offset + 40,
      length - 40,
      nextProto,
      collector,
      mapping,
      coverage,
      packetIndex,
      intents,
    );
  } else {
    coverage.push({ protocol: 'icmp-embedded', offset, length, status: 'malformed' });
  }

  return coverage;
}

/**
 * ICMPv6 Neighbor Discovery — map Source/Target Link-Layer Address options (CF-13).
 * Returns null when the message is not an NDP type.
 */
export function sanitizeIcmpv6Ndp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  icmpType: number,
  collector: PatchCollector,
  mapping: MappingLike,
  identity?: TunnelIdentityContext,
): LayerCoverage[] | null {
  if (
    icmpType !== NDP_RS
    && icmpType !== NDP_RA
    && icmpType !== NDP_NS
    && icmpType !== NDP_NA
    && icmpType !== NDP_REDIRECT
  ) {
    return null;
  }

  const coverage: LayerCoverage[] = [];
  const packetIndex = identity?.packetIndex ?? 0;
  const intents = identity?.intents;

  let optionsOffset: number;
  switch (icmpType) {
    case NDP_RS:
      optionsOffset = offset + 8;
      break;
    case NDP_RA:
      optionsOffset = offset + 16;
      break;
    case NDP_NS:
    case NDP_NA:
      if (length < 24) {
        coverage.push({ protocol: 'ndp', offset, length, status: 'malformed' });
        return coverage;
      }
      // Target Address (16 bytes) — IPv6 identity
      patchIpv6(buffer, offset + 8, collector, mapping, packetIndex, intents);
      optionsOffset = offset + 24;
      break;
    case NDP_REDIRECT:
      if (length < 40) {
        coverage.push({ protocol: 'ndp', offset, length, status: 'malformed' });
        return coverage;
      }
      patchIpv6(buffer, offset + 8, collector, mapping, packetIndex, intents);
      patchIpv6(buffer, offset + 24, collector, mapping, packetIndex, intents);
      optionsOffset = offset + 40;
      break;
    default:
      return null;
  }

  const fixedLen = optionsOffset - offset;
  coverage.push({ protocol: 'ndp', offset, length: Math.min(fixedLen, length), status: 'covered' });

  let cursor = optionsOffset;
  const end = offset + length;
  while (cursor + 2 <= end) {
    const optType = buffer[cursor]!;
    const optLen = buffer[cursor + 1]!;
    if (optLen === 0) {
      coverage.push({
        protocol: 'ndp-option',
        offset: cursor,
        length: end - cursor,
        status: 'malformed',
      });
      return coverage;
    }
    const optBytes = optLen * 8;
    if (cursor + optBytes > end) {
      coverage.push({
        protocol: 'ndp-option',
        offset: cursor,
        length: end - cursor,
        status: 'malformed',
      });
      return coverage;
    }

    if ((optType === 1 || optType === 2) && optBytes >= 8) {
      // Source / Target Link-Layer Address — Ethernet MAC in first 6 data bytes
      patchMac(buffer, cursor + 2, collector, mapping, packetIndex, intents);
      coverage.push({
        protocol: optType === 1 ? 'ndp-sll' : 'ndp-tll',
        offset: cursor,
        length: optBytes,
        status: 'covered',
      });
    } else if (optType === 3 && optBytes >= 32) {
      // Prefix Information (RFC 4861) — prefix at +16, length 16
      patchIpv6(buffer, cursor + 16, collector, mapping, packetIndex, intents);
      coverage.push({
        protocol: 'ndp-prefix',
        offset: cursor,
        length: optBytes,
        status: 'covered',
      });
    } else if (optType === 25 && optBytes >= 24) {
      // Recursive DNS Server (RFC 8106) — one or more IPv6 addresses after 8-byte header
      let addrOff = cursor + 8;
      const optEnd = cursor + optBytes;
      while (addrOff + 16 <= optEnd) {
        patchIpv6(buffer, addrOff, collector, mapping, packetIndex, intents);
        addrOff += 16;
      }
      coverage.push({
        protocol: 'ndp-rdnss',
        offset: cursor,
        length: optBytes,
        status: 'covered',
      });
    } else if (optType === 24 && optBytes >= 16) {
      // Route Information (RFC 4191) — prefix after 8-byte header when prefix-length > 0
      const prefixLen = buffer[cursor + 2]!;
      if (prefixLen > 0 && optBytes >= 16) {
        patchIpv6(buffer, cursor + 8, collector, mapping, packetIndex, intents);
      }
      coverage.push({
        protocol: 'ndp-route-info',
        offset: cursor,
        length: optBytes,
        status: 'covered',
      });
    } else {
      // Unknown options: leave bytes, mark unsupported (not silently covered)
      coverage.push({
        protocol: 'ndp-option',
        offset: cursor,
        length: optBytes,
        status: 'unsupported',
      });
    }
    cursor += optBytes;
  }

  if (cursor < end) {
    coverage.push({
      protocol: 'ndp-option',
      offset: cursor,
      length: end - cursor,
      status: 'malformed',
    });
  }

  return coverage;
}

/**
 * Detect if a UDP payload is VXLAN and sanitize recursively.
 */
export function sanitizeVxlan(
  buffer: Uint8Array,
  offset: number,
  length: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  depth: number = 0,
  onInnerTransport?: InnerTransportHandler,
  identity?: TunnelIdentityContext,
): TunnelResult | null {
  if (dstPort !== VXLAN_UDP_PORT) return null;
  if (length < 8) return null;

  const coverage: LayerCoverage[] = [];

  if (depth >= MAX_TUNNEL_DEPTH) {
    coverage.push({ protocol: 'vxlan', offset, length, status: 'unsupported' });
    return { coverage, depthExceeded: true };
  }

  const innerOffset = offset + 8;
  const innerLength = length - 8;
  coverage.push({ protocol: 'vxlan', offset, length: 8, status: 'covered' });

  const eth = sanitizeLinkedEthernet(
    buffer,
    innerOffset,
    innerLength,
    collector,
    mapping,
    depth,
    onInnerTransport,
    identity,
    'vxlan-ethernet',
    'vxlan-payload',
  );
  coverage.push(...eth.coverage);
  return { coverage, depthExceeded: eth.depthExceeded, drop: eth.drop };
}

/**
 * Shared Ethernet (optional VLAN) → IPv4/IPv6 walk for VXLAN/TZSP inner frames (T35).
 */
export function sanitizeLinkedEthernet(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  depth: number,
  onInnerTransport?: InnerTransportHandler,
  identity?: TunnelIdentityContext,
  ethernetProtocol: string = 'ethernet',
  unknownPayloadProtocol: string = 'ethernet-payload',
): TunnelResult {
  const coverage: LayerCoverage[] = [];
  const packetIndex = identity?.packetIndex ?? 0;
  const intents = identity?.intents;

  if (length < 14) {
    coverage.push({ protocol: ethernetProtocol, offset, length, status: 'malformed' });
    return { coverage, depthExceeded: false };
  }

  patchMac(buffer, offset, collector, mapping, packetIndex, intents);
  patchMac(buffer, offset + 6, collector, mapping, packetIndex, intents);
  coverage.push({ protocol: ethernetProtocol, offset, length: 14, status: 'covered' });

  let etherType = (buffer[offset + 12]! << 8) | buffer[offset + 13]!;
  let payloadOffset = offset + 14;
  let payloadLength = length - 14;

  const vlanIssues: string[] = [];
  while ((etherType === 0x8100 || etherType === 0x88a8) && payloadLength >= 4) {
    patchVlanTci(
      buffer,
      payloadOffset,
      collector,
      mapping,
      packetIndex,
      intents,
      coverage,
      vlanIssues,
    );
    etherType = (buffer[payloadOffset + 2]! << 8) | buffer[payloadOffset + 3]!;
    payloadOffset += 4;
    payloadLength -= 4;
  }
  void vlanIssues;

  if (etherType === 0x0800 && payloadLength >= 20) {
    const result = decodeInnerIpv4(
      buffer, payloadOffset, payloadLength, collector, mapping, depth + 1, [], onInnerTransport, identity,
    );
    coverage.push(...result.coverage);
    return { coverage, depthExceeded: result.depthExceeded, drop: result.drop };
  }
  if (etherType === 0x86dd && payloadLength >= 40) {
    const result = decodeInnerIpv6(
      buffer, payloadOffset, payloadLength, collector, mapping, depth + 1, [], onInnerTransport, identity,
    );
    coverage.push(...result.coverage);
    return { coverage, depthExceeded: result.depthExceeded, drop: result.drop };
  }

  if (payloadLength > 0) {
    coverage.push({
      protocol: unknownPayloadProtocol,
      offset: payloadOffset,
      length: payloadLength,
      status: 'unsupported',
    });
  }
  return { coverage, depthExceeded: false };
}

function appendEmbeddedTransport(
  buffer: Uint8Array,
  offset: number,
  length: number,
  nextProto: number,
  collector: PatchCollector,
  mapping: MappingLike,
  coverage: LayerCoverage[],
  packetIndex: number,
  intents?: IntentCollector,
): void {
  if (length <= 0) return;

  if (nextProto !== IP_PROTO_TCP && nextProto !== IP_PROTO_UDP) {
    coverage.push({
      protocol: 'icmp-embedded-payload',
      offset,
      length,
      status: 'unsupported',
    });
    return;
  }

  const proto = nextProto === IP_PROTO_TCP ? 'tcp' : 'udp';
  if (length < 4) {
    // Incomplete ports — do not claim covered
    coverage.push({
      protocol: 'icmp-embedded-payload',
      offset,
      length,
      status: 'unsupported',
    });
    return;
  }

  const srcPort = (buffer[offset]! << 8) | buffer[offset + 1]!;
  const dstPort = (buffer[offset + 2]! << 8) | buffer[offset + 3]!;
  patchPort(buffer, offset, proto, srcPort, collector, mapping, packetIndex, intents);
  patchPort(buffer, offset + 2, proto, dstPort, collector, mapping, packetIndex, intents);
  coverage.push({ protocol: 'icmp-embedded-ports', offset, length: 4, status: 'covered' });

  if (length > 4) {
    // Partial TCP seq/ack etc. — never mark covered (CF-13 / CF-11)
    coverage.push({
      protocol: 'icmp-embedded-payload',
      offset: offset + 4,
      length: length - 4,
      status: 'unsupported',
    });
  }
}

function decodeInnerIpv4(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  depth: number,
  coverage: LayerCoverage[],
  onInnerTransport?: InnerTransportHandler,
  identity?: TunnelIdentityContext,
): TunnelResult {
  const packetIndex = identity?.packetIndex ?? 0;
  const intents = identity?.intents;

  if (length < 20) {
    coverage.push({ protocol: 'ipip-ipv4', offset, length, status: 'malformed' });
    return { coverage, depthExceeded: false };
  }

  const ihl = (buffer[offset]! & 0xf) * 4;
  if (ihl < 20 || ihl > length) {
    coverage.push({ protocol: 'ipip-ipv4', offset, length, status: 'malformed' });
    return { coverage, depthExceeded: false };
  }

  patchIpv4(buffer, offset + 12, collector, mapping, packetIndex, intents);
  patchIpv4(buffer, offset + 16, collector, mapping, packetIndex, intents);
  coverage.push({ protocol: 'ipip-ipv4', offset, length: ihl, status: 'covered' });

  const nextProto = buffer[offset + 9]!;
  const payloadOffset = offset + ihl;
  const payloadLength = length - ihl;
  const srcIp = formatIpv4(buffer, offset + 12);
  const dstIp = formatIpv4(buffer, offset + 16);

  if (nextProto === IP_PROTO_IPIP || nextProto === IP_PROTO_IPV6 || nextProto === IP_PROTO_GRE) {
    const inner = sanitizeTunnel(
      buffer, payloadOffset, payloadLength, nextProto, collector, mapping, depth + 1, onInnerTransport, identity,
    );
    coverage.push(...inner.coverage);
    return { coverage, depthExceeded: inner.depthExceeded, drop: inner.drop };
  }

  if (onInnerTransport && payloadLength > 0) {
    const continued = onInnerTransport({
      offset: payloadOffset,
      ipProto: nextProto,
      isIpv6: false,
      srcIp,
      dstIp,
      depth: depth + 1,
    });
    coverage.push(...continued.coverage);
    return { coverage, depthExceeded: false, drop: continued.drop };
  }

  if (payloadLength > 0) {
    coverage.push({
      protocol: 'ipip-payload',
      offset: payloadOffset,
      length: payloadLength,
      status: 'unsupported',
    });
  }
  return { coverage, depthExceeded: false };
}

function decodeInnerIpv6(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  depth: number,
  coverage: LayerCoverage[],
  onInnerTransport?: InnerTransportHandler,
  identity?: TunnelIdentityContext,
): TunnelResult {
  const packetIndex = identity?.packetIndex ?? 0;
  const intents = identity?.intents;

  if (length < 40) {
    coverage.push({ protocol: 'ipip-ipv6', offset, length, status: 'malformed' });
    return { coverage, depthExceeded: false };
  }

  patchIpv6(buffer, offset + 8, collector, mapping, packetIndex, intents);
  patchIpv6(buffer, offset + 24, collector, mapping, packetIndex, intents);
  coverage.push({ protocol: 'ipip-ipv6', offset, length: 40, status: 'covered' });

  const nextHeader = buffer[offset + 6]!;
  const payloadOffset = offset + 40;
  const payloadLength = length - 40;
  const srcIp = formatIpv6(buffer, offset + 8);
  const dstIp = formatIpv6(buffer, offset + 24);

  if (nextHeader === IP_PROTO_IPIP || nextHeader === IP_PROTO_IPV6 || nextHeader === IP_PROTO_GRE) {
    const inner = sanitizeTunnel(
      buffer, payloadOffset, payloadLength, nextHeader, collector, mapping, depth + 1, onInnerTransport, identity,
    );
    coverage.push(...inner.coverage);
    return { coverage, depthExceeded: inner.depthExceeded, drop: inner.drop };
  }

  if (onInnerTransport && payloadLength > 0) {
    const continued = onInnerTransport({
      offset: payloadOffset,
      ipProto: nextHeader,
      isIpv6: true,
      srcIp,
      dstIp,
      depth: depth + 1,
    });
    coverage.push(...continued.coverage);
    return { coverage, depthExceeded: false, drop: continued.drop };
  }

  if (payloadLength > 0) {
    coverage.push({
      protocol: 'ipip-payload',
      offset: payloadOffset,
      length: payloadLength,
      status: 'unsupported',
    });
  }
  return { coverage, depthExceeded: false };
}

function decodeGre(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  depth: number,
  coverage: LayerCoverage[],
  onInnerTransport?: InnerTransportHandler,
  identity?: TunnelIdentityContext,
): TunnelResult {
  if (length < 4) {
    coverage.push({ protocol: 'gre', offset, length, status: 'malformed' });
    return { coverage, depthExceeded: false };
  }

  const flags = (buffer[offset]! << 8) | buffer[offset + 1]!;
  const protocol = (buffer[offset + 2]! << 8) | buffer[offset + 3]!;

  let headerSize = 4;
  if (flags & 0x8000) headerSize += 4;
  if (flags & 0x2000) headerSize += 4;
  if (flags & 0x1000) headerSize += 4;

  if (headerSize > length) {
    coverage.push({ protocol: 'gre', offset, length, status: 'malformed' });
    return { coverage, depthExceeded: false };
  }

  coverage.push({ protocol: 'gre', offset, length: headerSize, status: 'covered' });

  const payloadOffset = offset + headerSize;
  const payloadLength = length - headerSize;

  if (protocol === 0x0800 && payloadLength >= 20) {
    return decodeInnerIpv4(
      buffer, payloadOffset, payloadLength, collector, mapping, depth + 1, coverage, onInnerTransport, identity,
    );
  }
  if (protocol === 0x86dd && payloadLength >= 40) {
    return decodeInnerIpv6(
      buffer, payloadOffset, payloadLength, collector, mapping, depth + 1, coverage, onInnerTransport, identity,
    );
  }

  // T34 — ERSPAN II (0x88BE) / III (0x22EB): session map + mirrored Ethernet
  if ((protocol === 0x88be || protocol === 0x22eb) && payloadLength >= 8) {
    const packetIndex = identity?.packetIndex ?? 0
    const intents = identity?.intents
    const hdrLen = protocol === 0x88be ? 8 : Math.min(12, payloadLength)
    // Session ID in bits of first words — map 2-byte session field at +2 (II) / composite (III)
    const sessOff = payloadOffset + 2
    const sess = (buffer[sessOff]! << 8) | buffer[sessOff + 1]!
    const canon = `erspan-session/${sess}`
    intents?.recordEntityReplacement(packetIndex, sessOff, 'opaque-id', canon, 2)
    collector.addDeferred(sessOff, 2, ({ mapping: live }) => {
      const alias = live.map('opaque-id', canon)
      return createProtocolNeutralMaskFill({
        length: 2,
        packetIndex,
        offset: sessOff,
        domain: `erspan:${alias}`,
      })
    })
    coverage.push({ protocol: 'erspan', offset: payloadOffset, length: hdrLen, status: 'covered' })
    const ethOff = payloadOffset + hdrLen
    const ethLen = payloadLength - hdrLen
    if (ethLen >= 14) {
      const eth = sanitizeLinkedEthernet(
        buffer,
        ethOff,
        ethLen,
        collector,
        mapping,
        depth + 1,
        onInnerTransport,
        identity,
      )
      coverage.push(...eth.coverage)
      return { coverage, depthExceeded: eth.depthExceeded, drop: eth.drop }
    }
  }

  if (payloadLength > 0) {
    coverage.push({ protocol: 'gre-payload', offset: payloadOffset, length: payloadLength, status: 'unsupported' });
  }
  return { coverage, depthExceeded: false };
}

function patchIpv4(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const ip = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
  if (ip === '0.0.0.0') return;
  if (intents) intents.recordEntityReplacement(packetIndex, offset, 'ipv4', ip, 4);
  try {
    collector.addDeferred(offset, 4, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('ipv4', ip);
      return new Uint8Array(mapped.split('.').map(Number));
    });
  } catch { /* overlap */ }
}

function patchIpv6(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const ip = formatIpv6(buffer, offset);
  if (intents) intents.recordEntityReplacement(packetIndex, offset, 'ipv6', ip, 16);
  try {
    collector.addDeferred(offset, 16, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('ipv6', ip);
      const mappedParts = mapped.split(':').filter((p) => p !== '');
      const bytes = new Uint8Array(16);
      let idx = 0;
      for (const p of mappedParts) {
        const val = parseInt(p, 16);
        if (idx + 1 < 16) {
          bytes[idx++] = (val >> 8) & 0xff;
          bytes[idx++] = val & 0xff;
        }
      }
      return bytes;
    });
  } catch { /* overlap */ }
}

function patchMac(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const mac = Array.from(buffer.slice(offset, offset + 6))
    .map((b) => b.toString(16).padStart(2, '0')).join(':');
  if (intents) intents.recordEntityReplacement(packetIndex, offset, 'mac', mac, 6);
  try {
    collector.addDeferred(offset, 6, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('mac', mac);
      return new Uint8Array(mapped.split(':').map((s) => parseInt(s, 16)));
    });
  } catch { /* overlap */ }
}

function patchPort(
  _buffer: Uint8Array,
  offset: number,
  proto: 'tcp' | 'udp',
  port: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const canonical = `${proto}/${port}`;
  if (intents) intents.recordEntityReplacement(packetIndex, offset, 'port', canonical, 2);
  try {
    collector.addDeferred(offset, 2, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('port', canonical);
      const slash = mapped.indexOf('/');
      if (slash < 0) return null;
      const mappedPort = Number.parseInt(mapped.slice(slash + 1), 10);
      if (!Number.isInteger(mappedPort) || mappedPort < 0 || mappedPort > 65535 || mappedPort === port) return null;
      return new Uint8Array([(mappedPort >> 8) & 0xff, mappedPort & 0xff]);
    });
  } catch { /* overlap */ }
}

function formatIpv4(buffer: Uint8Array, offset: number): string {
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}

function formatIpv6(buffer: Uint8Array, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((buffer[offset + i]! << 8) | buffer[offset + i + 1]!).toString(16));
  }
  return parts.join(':');
}
