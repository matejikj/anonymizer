/**
 * RTP/RTCP payload shape validation (step 8 / CF-03).
 * Port-only matching is insufficient — callers combine SDP keys and flow evidence.
 */

const RTP_MIN_BYTES = 12;
const RTCP_MIN_BYTES = 8;

export function rtpVersion(data: Uint8Array, offset: number): number | null {
  if (offset >= data.length) return null;
  return (data[offset]! >> 6) & 0x3;
}

export interface RtpHeaderFields {
  readonly version: number;
  readonly padding: boolean;
  readonly extension: boolean;
  readonly csrcCount: number;
  readonly marker: boolean;
  readonly payloadType: number;
  readonly sequence: number;
  readonly timestamp: number;
  readonly ssrc: number;
  readonly headerLength: number;
}

export function parseRtpHeader(
  data: Uint8Array,
  offset: number,
  length: number,
): RtpHeaderFields | null {
  if (length < RTP_MIN_BYTES) return null;
  if (rtpVersion(data, offset) !== 2) return null;

  const b0 = data[offset]!;
  const b1 = data[offset + 1]!;
  const csrcCount = b0 & 0x0f;
  let headerLength = 12 + csrcCount * 4;
  if (length < headerLength) return null;

  const extension = ((b0 >> 4) & 0x1) === 1;
  if (extension) {
    if (length < headerLength + 4) return null;
    const extLenWords = (data[offset + headerLength + 2]! << 8) | data[offset + headerLength + 3]!;
    headerLength += 4 + extLenWords * 4;
    if (length < headerLength) return null;
  }

  return {
    version: 2,
    padding: ((b0 >> 5) & 0x1) === 1,
    extension,
    csrcCount,
    marker: ((b1 >> 7) & 0x1) === 1,
    payloadType: b1 & 0x7f,
    sequence: (data[offset + 2]! << 8) | data[offset + 3]!,
    timestamp:
      ((data[offset + 4]! << 24) >>> 0)
      + (data[offset + 5]! << 16)
      + (data[offset + 6]! << 8)
      + data[offset + 7]!,
    ssrc:
      ((data[offset + 8]! << 24) >>> 0)
      + (data[offset + 9]! << 16)
      + (data[offset + 10]! << 8)
      + data[offset + 11]!,
    headerLength,
  };
}

export function looksLikeRtpPayload(
  data: Uint8Array,
  offset: number,
  length: number,
  expectedPayloadTypes: readonly string[] = [],
): boolean {
  const header = parseRtpHeader(data, offset, length);
  if (!header) return false;

  if (expectedPayloadTypes.length === 0) return true;

  const ptText = String(header.payloadType);
  if (expectedPayloadTypes.includes(ptText)) return true;

  // Dynamic PT 96–127: accept when SDP advertises any dynamic PT in range.
  if (header.payloadType >= 96 && header.payloadType <= 127) {
    return expectedPayloadTypes.some((t) => {
      const n = Number.parseInt(t, 10);
      return Number.isInteger(n) && n >= 96 && n <= 127;
    });
  }

  return false;
}

export function looksLikeRtcpPayload(data: Uint8Array, offset: number, length: number): boolean {
  if (length < RTCP_MIN_BYTES) return false;
  if (rtpVersion(data, offset) !== 2) return false;
  const packetType = data[offset + 1]!;
  // RFC 3550: 200=SR, 201=RR, 202=SDES, 203=BYE, 204=APP, 207=XR, …
  if (packetType < 192 || packetType > 211) return false;

  // Compound length must be consistent for at least the first packet.
  const words = (data[offset + 2]! << 8) | data[offset + 3]!;
  const packetBytes = (words + 1) * 4;
  if (packetBytes < RTCP_MIN_BYTES || packetBytes > length) return false;
  return true;
}

export type MediaShapeKind = 'rtp' | 'rtcp';

export function detectMediaShape(
  data: Uint8Array,
  offset: number,
  length: number,
): MediaShapeKind | null {
  if (looksLikeRtcpPayload(data, offset, length)) return 'rtcp';
  if (looksLikeRtpPayload(data, offset, length)) return 'rtp';
  return null;
}
