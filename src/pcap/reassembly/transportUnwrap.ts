/**
 * Strip transport headers from IP-reassembled datagrams before SIP parsing (CF-05).
 */

import type { ByteProvenance, ReassembledView } from './types';

const IPPROTO_TCP = 6;
const IPPROTO_UDP = 17;

/**
 * Convert a complete IP-reassembled L4 datagram into an application-layer view.
 * Strips UDP (8) or TCP (data-offset) headers and shifts provenance accordingly.
 */
export function unwrapTransportDatagram(view: ReassembledView): ReassembledView | null {
  if (view.status !== 'complete') return null;
  const ipProto = view.ipProto ?? (view.transport === 'tcp' ? IPPROTO_TCP : IPPROTO_UDP);

  if (ipProto === IPPROTO_UDP) {
    if (view.bytes.length < 8) return null;
    const udpLenField = (view.bytes[4]! << 8) | view.bytes[5]!;
    const udpLen = (udpLenField >= 8 && udpLenField <= view.bytes.length)
      ? udpLenField
      : view.bytes.length;
    return sliceAppView(view, 8, udpLen - 8, 'udp', IPPROTO_UDP);
  }

  if (ipProto === IPPROTO_TCP) {
    if (view.bytes.length < 20) return null;
    const dataOffset = (view.bytes[12]! >> 4) * 4;
    if (dataOffset < 20 || dataOffset > view.bytes.length) return null;
    return sliceAppView(view, dataOffset, view.bytes.length - dataOffset, 'tcp', IPPROTO_TCP);
  }

  return null;
}

function sliceAppView(
  view: ReassembledView,
  headerLen: number,
  appLen: number,
  transport: 'tcp' | 'udp',
  ipProto: number,
): ReassembledView | null {
  if (appLen < 0) return null;
  const bytes = view.bytes.subarray(headerLen, headerLen + appLen);
  return {
    bytes: bytes.slice(),
    provenance: shiftProvenance(view.provenance, headerLen, appLen),
    transport,
    flowKey: view.flowKey,
    packetIndices: view.packetIndices,
    status: 'complete',
    ipProto,
  };
}

function shiftProvenance(
  provenance: readonly ByteProvenance[],
  headerLen: number,
  appLen: number,
): ByteProvenance[] {
  const out: ByteProvenance[] = [];
  for (const p of provenance) {
    const pEnd = p.assembledOffset + p.length;
    if (pEnd <= headerLen) continue;
    if (p.assembledOffset >= headerLen + appLen) continue;
    const skip = Math.max(0, headerLen - p.assembledOffset);
    const assembledOffset = Math.max(0, p.assembledOffset - headerLen);
    const length = Math.min(p.length - skip, appLen - assembledOffset);
    if (length <= 0) continue;
    out.push({
      assembledOffset,
      packetIndex: p.packetIndex,
      packetOffset: p.packetOffset + skip,
      length,
    });
  }
  return out;
}

export { IPPROTO_TCP, IPPROTO_UDP };
