/**
 * Parse link/network/transport fields needed for reassembly (step 9).
 */

import { locateLayers } from '../checksums/locate';
import type { FlowEndpoint } from './types';

export interface ParsedTcpSegment {
  readonly packetIndex: number;
  readonly endpoint: FlowEndpoint;
  readonly seq: number;
  readonly payloadOffset: number;
  readonly payloadLength: number;
  readonly syn: boolean;
  readonly fin: boolean;
  readonly rst: boolean;
  readonly isFragment: boolean;
}

export interface ParsedIpv4Fragment {
  readonly packetIndex: number;
  readonly srcIp: string;
  readonly dstIp: string;
  readonly ipProto: number;
  readonly identification: number;
  readonly fragmentOffset: number;
  readonly moreFragments: boolean;
  readonly payloadOffset: number;
  readonly payloadLength: number;
}

export interface ParsedIpv6Fragment {
  readonly packetIndex: number;
  readonly srcIp: string;
  readonly dstIp: string;
  readonly identification: number;
  readonly fragmentOffset: number;
  readonly moreFragments: boolean;
  readonly nextHeader: number;
  readonly payloadOffset: number;
  readonly payloadLength: number;
}

function formatIpv4(data: Uint8Array, offset: number): string {
  return `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
}

function formatIpv6(data: Uint8Array, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((data[offset + i]! << 8) | data[offset + i + 1]!).toString(16));
  }
  return parts.join(':');
}

function readIpv6FragmentHeader(
  data: Uint8Array,
  l3Offset: number,
  capturedLen: number,
): ParsedIpv6Fragment | null {
  if (l3Offset + 40 > capturedLen) return null;
  const srcIp = formatIpv6(data, l3Offset + 8);
  const dstIp = formatIpv6(data, l3Offset + 24);
  let nextHeader = data[l3Offset + 6]!;
  let hdrOff = l3Offset + 40;

  while (hdrOff + 8 <= capturedLen) {
    if (nextHeader === 44) {
      const identification =
        (data[hdrOff + 4]! << 24) |
        (data[hdrOff + 5]! << 16) |
        (data[hdrOff + 6]! << 8) |
        data[hdrOff + 7]!;
      const fragOffset = (((data[hdrOff + 2]! << 8) | data[hdrOff + 3]!) >> 3) * 8;
      const moreFragments = (data[hdrOff + 3]! & 0x01) !== 0;
      const payloadOffset = hdrOff + 8;
      return {
        packetIndex: 0,
        srcIp,
        dstIp,
        identification,
        fragmentOffset: fragOffset,
        moreFragments,
        nextHeader: data[hdrOff]!,
        payloadOffset,
        payloadLength: capturedLen - payloadOffset,
      };
    }
    if (nextHeader === 0 || nextHeader === 43 || nextHeader === 60) {
      const extLen = (data[hdrOff + 1]! + 1) * 8;
      nextHeader = data[hdrOff]!;
      hdrOff += extLen;
      continue;
    }
    if (nextHeader === 51) {
      const ahLen = (data[hdrOff + 1]! + 2) * 4;
      nextHeader = data[hdrOff]!;
      hdrOff += ahLen;
      continue;
    }
    break;
  }
  return null;
}

export function parseTcpSegment(
  data: Uint8Array,
  linkType: number,
  capturedLen: number,
  packetIndex: number,
): ParsedTcpSegment | null {
  const layers = locateLayers(data, linkType, capturedLen);
  if (layers.l4Proto !== 'tcp' || layers.isFragment) return null;
  if (layers.l4Offset + 20 > capturedLen) return null;

  const tcpOff = layers.l4Offset;
  const dataOffsetField = (data[tcpOff + 12]! >> 4) * 4;
  if (dataOffsetField < 20 || tcpOff + dataOffsetField > capturedLen) return null;

  const srcPort = (data[tcpOff]! << 8) | data[tcpOff + 1]!;
  const dstPort = (data[tcpOff + 2]! << 8) | data[tcpOff + 3]!;
  const seq =
    (data[tcpOff + 4]! << 24) |
    (data[tcpOff + 5]! << 16) |
    (data[tcpOff + 6]! << 8) |
    data[tcpOff + 7]!;
  const flags = data[tcpOff + 13]!;
  const payloadOffset = tcpOff + dataOffsetField;
  const payloadLength = capturedLen - payloadOffset;

  let srcIp = '';
  let dstIp = '';
  if (layers.l3Proto === 'ipv4') {
    srcIp = formatIpv4(data, layers.l3Offset + 12);
    dstIp = formatIpv4(data, layers.l3Offset + 16);
  } else if (layers.l3Proto === 'ipv6') {
    srcIp = formatIpv6(data, layers.l3Offset + 8);
    dstIp = formatIpv6(data, layers.l3Offset + 24);
  } else {
    return null;
  }

  return {
    packetIndex,
    endpoint: { srcIp, dstIp, srcPort, dstPort, ipProto: 6 },
    seq,
    payloadOffset,
    payloadLength,
    syn: (flags & 0x02) !== 0,
    fin: (flags & 0x01) !== 0,
    rst: (flags & 0x04) !== 0,
    isFragment: layers.isFragment,
  };
}

export function parseIpv4Fragment(
  data: Uint8Array,
  linkType: number,
  capturedLen: number,
  packetIndex: number,
): ParsedIpv4Fragment | null {
  const layers = locateLayers(data, linkType, capturedLen);
  if (layers.l3Proto !== 'ipv4' || !layers.isFragment) return null;

  const l3 = layers.l3Offset;
  const fragOffset = (((data[l3 + 6]! & 0x1f) << 8) | data[l3 + 7]!) * 8;
  const moreFragments = (data[l3 + 6]! & 0x20) !== 0;
  const identification = (data[l3 + 4]! << 8) | data[l3 + 5]!;
  const ipProto = data[l3 + 9]!;

  const payloadOffset = layers.l4Offset;
  const payloadLength = capturedLen - payloadOffset;

  return {
    packetIndex,
    srcIp: formatIpv4(data, l3 + 12),
    dstIp: formatIpv4(data, l3 + 16),
    ipProto,
    identification,
    fragmentOffset: fragOffset,
    moreFragments,
    payloadOffset,
    payloadLength,
  };
}

export function parseIpv6Fragment(
  data: Uint8Array,
  linkType: number,
  capturedLen: number,
  packetIndex: number,
): ParsedIpv6Fragment | null {
  const layers = locateLayers(data, linkType, capturedLen);
  if (layers.l3Proto !== 'ipv6' || !layers.isFragment) return null;

  const frag = readIpv6FragmentHeader(data, layers.l3Offset, capturedLen);
  if (!frag) return null;
  return { ...frag, packetIndex };
}

export function isSipPort(srcPort: number, dstPort: number): boolean {
  return srcPort === 5060 || dstPort === 5060 || srcPort === 5061 || dstPort === 5061;
}

const HTTP_PORTS = new Set([80, 8080, 8000, 8008, 8888, 3128, 8081]);

export function isHttpPort(srcPort: number, dstPort: number): boolean {
  return HTTP_PORTS.has(srcPort) || HTTP_PORTS.has(dstPort);
}

const CHUNK_DATA = 0;
const CHUNK_I_DATA = 64;
const MAX_SCTP_CHUNKS_PER_PACKET = 64;

/** One DATA / I-DATA user-data fragment extracted for SCTP message reassembly (T17/V15). */
export interface ParsedSctpDataFragment {
  readonly packetIndex: number;
  readonly endpoint: FlowEndpoint;
  readonly verificationTag: number;
  readonly isIdata: boolean;
  readonly unordered: boolean;
  readonly beginning: boolean;
  readonly ending: boolean;
  readonly tsn: number;
  readonly streamId: number;
  /** DATA: Stream Sequence Number; I-DATA: Message Identifier. */
  readonly messageId: number;
  /** I-DATA Fragment Sequence Number; 0 for DATA (order by TSN instead). */
  readonly fsn: number;
  readonly ppid: number;
  /** Absolute offset of user-data bytes in the capture packet. */
  readonly userOffset: number;
  readonly userLength: number;
  readonly captureOrder: number;
}

/**
 * Parse SCTP DATA / I-DATA chunk fragments from a packet (RFC 9260 / RFC 8260).
 * Returns null when the packet is not SCTP or has no DATA/I-DATA chunks.
 */
export function parseSctpDataFragments(
  data: Uint8Array,
  linkType: number,
  capturedLen: number,
  packetIndex: number,
  captureOrderStart = 0,
): ParsedSctpDataFragment[] | null {
  const layers = locateLayers(data, linkType, capturedLen);
  if (layers.l4Proto !== 'sctp' || layers.isFragment) return null;
  if (layers.l4Offset + 12 > capturedLen) return null;

  const sctpOff = layers.l4Offset;
  const srcPort = (data[sctpOff]! << 8) | data[sctpOff + 1]!;
  const dstPort = (data[sctpOff + 2]! << 8) | data[sctpOff + 3]!;
  const verificationTag =
    ((data[sctpOff + 4]! << 24)
      | (data[sctpOff + 5]! << 16)
      | (data[sctpOff + 6]! << 8)
      | data[sctpOff + 7]!)
    >>> 0;

  let srcIp = '';
  let dstIp = '';
  if (layers.l3Proto === 'ipv4') {
    srcIp = formatIpv4(data, layers.l3Offset + 12);
    dstIp = formatIpv4(data, layers.l3Offset + 16);
  } else if (layers.l3Proto === 'ipv6') {
    srcIp = formatIpv6(data, layers.l3Offset + 8);
    dstIp = formatIpv6(data, layers.l3Offset + 24);
  } else {
    return null;
  }

  const endpoint: FlowEndpoint = {
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    ipProto: 132,
  };

  const out: ParsedSctpDataFragment[] = [];
  let pos = sctpOff + 12;
  let chunkCount = 0;
  let captureOrder = captureOrderStart;

  while (pos + 4 <= capturedLen && chunkCount < MAX_SCTP_CHUNKS_PER_PACKET) {
    const type = data[pos]!;
    const flags = data[pos + 1]!;
    const length = (data[pos + 2]! << 8) | data[pos + 3]!;
    if (length < 4 || pos + length > capturedLen) break;

    if (type === CHUNK_DATA || type === CHUNK_I_DATA) {
      const isIdata = type === CHUNK_I_DATA;
      // RFC 8260 I-DATA header is 20 octets; PPID/FSN share offset +16 (B bit selects).
      const fixedLen = isIdata ? 20 : 16;
      if (length >= fixedLen) {
        const beginning = (flags & 0x02) !== 0;
        const ending = (flags & 0x01) !== 0;
        const unordered = (flags & 0x04) !== 0;
        const tsn =
          ((data[pos + 4]! << 24)
            | (data[pos + 5]! << 16)
            | (data[pos + 6]! << 8)
            | data[pos + 7]!)
          >>> 0;
        const streamId = (data[pos + 8]! << 8) | data[pos + 9]!;
        let messageId: number;
        let fsn: number;
        let ppid: number;
        if (isIdata) {
          messageId =
            ((data[pos + 12]! << 24)
              | (data[pos + 13]! << 16)
              | (data[pos + 14]! << 8)
              | data[pos + 15]!)
            >>> 0;
          const field16 =
            ((data[pos + 16]! << 24)
              | (data[pos + 17]! << 16)
              | (data[pos + 18]! << 8)
              | data[pos + 19]!)
            >>> 0;
          if (beginning) {
            ppid = field16;
            fsn = 0;
          } else {
            ppid = 0;
            fsn = field16;
          }
        } else {
          messageId = (data[pos + 10]! << 8) | data[pos + 11]!;
          fsn = 0;
          ppid =
            ((data[pos + 12]! << 24)
              | (data[pos + 13]! << 16)
              | (data[pos + 14]! << 8)
              | data[pos + 15]!)
            >>> 0;
        }
        const userOffset = pos + fixedLen;
        const userLength = pos + length - userOffset;
        // Only track fragmented messages here; complete B+E singles stay on per-packet path.
        if (userLength >= 0 && (!beginning || !ending)) {
          out.push({
            packetIndex,
            endpoint,
            verificationTag,
            isIdata,
            unordered,
            beginning,
            ending,
            tsn,
            streamId,
            messageId,
            fsn,
            ppid,
            userOffset,
            userLength,
            captureOrder: captureOrder++,
          });
        }
      }
    }

    pos += (length + 3) & ~3;
    chunkCount++;
  }

  return out.length > 0 ? out : null;
}
