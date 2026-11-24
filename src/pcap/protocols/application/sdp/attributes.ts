/**
 * SDP attribute (`a=`) parsers for ICE, RTCP, SDES, fingerprint.
 */

import type { ByteSpan } from '../sip/types';
import type {
  SdpAttribute,
  SdpCandidate,
  SdpCrypto,
  SdpFingerprint,
  SdpRemoteCandidate,
} from './types';
import { decodeLatin1Span, parseAttributeNameValue, spanOf, splitSpannedTokens } from './lines';

const EMPTY_REMOTE_CANDIDATES: readonly SdpRemoteCandidate[] = [];

function baseAttribute(
  buffer: Uint8Array,
  lineStart: number,
  lineBreak: number,
  valueStart: number,
  valueEnd: number,
  kind: SdpAttribute['kind'],
): Pick<SdpAttribute, 'span' | 'kind' | 'nameSpan' | 'valueSpan'> {
  const { nameSpan, valueSpan } = parseAttributeNameValue(buffer, valueStart, valueEnd);
  return {
    span: spanOf(lineStart, lineBreak),
    kind,
    nameSpan,
    valueSpan,
  };
}

function emptyFields(): Pick<
  SdpAttribute,
  'candidate' | 'remoteCandidates' | 'fingerprint' | 'crypto' | 'rtcpPort' | 'rtcpAddress' | 'rtcpAddrType' | 'extmapId' | 'extmapUri'
> {
  return {
    candidate: null,
    remoteCandidates: EMPTY_REMOTE_CANDIDATES,
    fingerprint: null,
    crypto: null,
    rtcpPort: null,
    rtcpAddress: null,
    rtcpAddrType: null,
    extmapId: null,
    extmapUri: null,
  };
}

export function parseSdpAttribute(
  buffer: Uint8Array,
  lineStart: number,
  lineBreak: number,
  valueStart: number,
  valueEnd: number,
): SdpAttribute {
  const { nameSpan, valueSpan } = parseAttributeNameValue(buffer, valueStart, valueEnd);
  const name = decodeLatin1Span(buffer, nameSpan).toLowerCase();
  const span = spanOf(lineStart, lineBreak);

  switch (name) {
    case 'rtcp':
      return parseRtcpAttribute(buffer, span, nameSpan, valueSpan);
    case 'candidate':
      return parseCandidateAttribute(buffer, span, nameSpan, valueSpan);
    case 'remote-candidates':
      return parseRemoteCandidatesAttribute(buffer, span, nameSpan, valueSpan);
    case 'ice-ufrag':
      return {
        ...baseAttribute(buffer, lineStart, lineBreak, valueStart, valueEnd, 'ice-ufrag'),
        ...emptyFields(),
      };
    case 'ice-pwd':
      return {
        ...baseAttribute(buffer, lineStart, lineBreak, valueStart, valueEnd, 'ice-pwd'),
        ...emptyFields(),
      };
    case 'fingerprint':
      return parseFingerprintAttribute(buffer, span, nameSpan, valueSpan);
    case 'crypto':
      return parseCryptoAttribute(buffer, span, nameSpan, valueSpan);
    case 'sendrecv':
    case 'sendonly':
    case 'recvonly':
    case 'inactive':
      return {
        span,
        kind: 'direction',
        nameSpan,
        valueSpan: spanOf(valueEnd, valueEnd),
        ...emptyFields(),
      };
    case 'rtcp-mux':
      return {
        span,
        kind: 'rtcp-mux',
        nameSpan,
        valueSpan,
        ...emptyFields(),
      };
    case 'extmap':
      return parseExtmapAttribute(buffer, span, nameSpan, valueSpan);
    // Codec/negotiation attributes: identify only which codecs/formats are in use, never a
    // host, person or credential. rtpmap/fmtp values are RTP payload-type + codec/DTMF
    // parameters (e.g. "8 PCMA/8000", "120 0-16"); X-nat is a NAT-traversal hint (an integer).
    case 'rtpmap':
    case 'fmtp':
    case 'x-nat':
      return {
        span,
        kind: 'preserve',
        nameSpan,
        valueSpan,
        ...emptyFields(),
      };
    default:
      return {
        span,
        kind: 'generic',
        nameSpan,
        valueSpan,
        ...emptyFields(),
      };
  }
}

function parseRtcpAttribute(
  buffer: Uint8Array,
  span: ByteSpan,
  nameSpan: ByteSpan,
  valueSpan: ByteSpan,
): SdpAttribute {
  const end = valueSpan.offset + valueSpan.length;
  const tokens = splitSpannedTokens(buffer, valueSpan.offset, end, 4);
  const rtcpPort = tokens[0] ?? null;
  let rtcpAddrType: ByteSpan | null = null;
  let rtcpAddress: ByteSpan | null = null;
  if (tokens.length >= 4) {
    rtcpAddrType = tokens[2] ?? null;
    rtcpAddress = tokens[3] ?? null;
  }
  return {
    span,
    kind: 'rtcp',
    nameSpan,
    valueSpan,
    candidate: null,
    remoteCandidates: EMPTY_REMOTE_CANDIDATES,
    fingerprint: null,
    crypto: null,
    rtcpPort,
    rtcpAddress,
    rtcpAddrType,
    extmapId: null,
    extmapUri: null,
  };
}

function parseRemoteCandidatesAttribute(
  buffer: Uint8Array,
  span: ByteSpan,
  nameSpan: ByteSpan,
  valueSpan: ByteSpan,
): SdpAttribute {
  const end = valueSpan.offset + valueSpan.length;
  const tokens = splitSpannedTokens(buffer, valueSpan.offset, end, 96);
  const remoteCandidates: SdpRemoteCandidate[] = [];
  for (let i = 0; i + 2 < tokens.length; i += 3) {
    remoteCandidates.push({
      componentId: tokens[i]!,
      address: tokens[i + 1]!,
      port: tokens[i + 2]!,
    });
  }
  return {
    span,
    kind: 'remote-candidates',
    nameSpan,
    valueSpan,
    candidate: null,
    remoteCandidates,
    fingerprint: null,
    crypto: null,
    rtcpPort: null,
    rtcpAddress: null,
    rtcpAddrType: null,
    extmapId: null,
    extmapUri: null,
  };
}

function parseCandidateAttribute(
  buffer: Uint8Array,
  span: ByteSpan,
  nameSpan: ByteSpan,
  valueSpan: ByteSpan,
): SdpAttribute {
  const end = valueSpan.offset + valueSpan.length;
  const tokens = splitSpannedTokens(buffer, valueSpan.offset, end, 32);
  const candidate = parseCandidateTokens(buffer, tokens);
  return {
    span,
    kind: 'candidate',
    nameSpan,
    valueSpan,
    candidate,
    remoteCandidates: EMPTY_REMOTE_CANDIDATES,
    fingerprint: null,
    crypto: null,
    rtcpPort: null,
    rtcpAddress: null,
    rtcpAddrType: null,
    extmapId: null,
    extmapUri: null,
  };
}

function parseCandidateTokens(buffer: Uint8Array, tokens: readonly ByteSpan[]): SdpCandidate | null {
  if (tokens.length < 6) return null;

  let typ: ByteSpan | null = null;
  let extensionStart = 6;
  for (let i = 6; i + 1 < tokens.length; i++) {
    if (decodeLatin1Span(buffer, tokens[i]!).toLowerCase() === 'typ') {
      typ = tokens[i + 1] ?? null;
      extensionStart = i + 2;
      break;
    }
  }

  let relatedAddress: ByteSpan | null = null;
  let relatedPort: ByteSpan | null = null;
  for (let i = extensionStart; i + 1 < tokens.length; i += 2) {
    const key = decodeLatin1Span(buffer, tokens[i]!).toLowerCase();
    if (key === 'raddr') relatedAddress = tokens[i + 1] ?? null;
    if (key === 'rport') relatedPort = tokens[i + 1] ?? null;
  }

  return {
    foundation: tokens[0]!,
    componentId: tokens[1]!,
    transport: tokens[2]!,
    priority: tokens[3]!,
    address: tokens[4]!,
    port: tokens[5]!,
    typ,
    relatedAddress,
    relatedPort,
  };
}

function parseFingerprintAttribute(
  buffer: Uint8Array,
  span: ByteSpan,
  nameSpan: ByteSpan,
  valueSpan: ByteSpan,
): SdpAttribute {
  const end = valueSpan.offset + valueSpan.length;
  const tokens = splitSpannedTokens(buffer, valueSpan.offset, end, 2);
  const fingerprint: SdpFingerprint | null = tokens.length >= 2
    ? { hashFunc: tokens[0]!, fingerprint: tokens[1]! }
    : null;

  return {
    span,
    kind: 'fingerprint',
    nameSpan,
    valueSpan,
    candidate: null,
    remoteCandidates: EMPTY_REMOTE_CANDIDATES,
    fingerprint,
    crypto: null,
    rtcpPort: null,
    rtcpAddress: null,
    rtcpAddrType: null,
    extmapId: null,
    extmapUri: null,
  };
}

function parseCryptoAttribute(
  buffer: Uint8Array,
  span: ByteSpan,
  nameSpan: ByteSpan,
  valueSpan: ByteSpan,
): SdpAttribute {
  const end = valueSpan.offset + valueSpan.length;
  const tokens = splitSpannedTokens(buffer, valueSpan.offset, end, 3);
  const crypto: SdpCrypto | null = tokens.length >= 3
    ? { tag: tokens[0]!, suite: tokens[1]!, keyParams: tokens[2]! }
    : null;

  return {
    span,
    kind: 'crypto',
    nameSpan,
    valueSpan,
    candidate: null,
    remoteCandidates: EMPTY_REMOTE_CANDIDATES,
    fingerprint: null,
    crypto,
    rtcpPort: null,
    rtcpAddress: null,
    rtcpAddrType: null,
    extmapId: null,
    extmapUri: null,
  };
}

/**
 * `a=extmap:<value>["/"<direction>] <URI> [<extensionattributes>]`
 * ID may be a range `1-5` — we take the first integer as the primary ID.
 */
function parseExtmapAttribute(
  buffer: Uint8Array,
  span: ByteSpan,
  nameSpan: ByteSpan,
  valueSpan: ByteSpan,
): SdpAttribute {
  const end = valueSpan.offset + valueSpan.length;
  const tokens = splitSpannedTokens(buffer, valueSpan.offset, end, 4);
  let extmapId: number | null = null;
  let extmapUri: ByteSpan | null = null;
  if (tokens.length >= 1) {
    const idText = decodeLatin1Span(buffer, tokens[0]!).split('/')[0] ?? ''
    const rangeStart = idText.split('-')[0] ?? ''
    const n = Number.parseInt(rangeStart, 10)
    if (Number.isInteger(n) && n >= 1 && n <= 255) extmapId = n
  }
  if (tokens.length >= 2) {
    extmapUri = tokens[1]!
  }
  return {
    span,
    kind: 'extmap',
    nameSpan,
    valueSpan,
    candidate: null,
    remoteCandidates: EMPTY_REMOTE_CANDIDATES,
    fingerprint: null,
    crypto: null,
    rtcpPort: null,
    rtcpAddress: null,
    rtcpAddrType: null,
    extmapId,
    extmapUri,
  };
}

export function readAttributeDirection(
  buffer: Uint8Array,
  attr: SdpAttribute,
): 'sendrecv' | 'sendonly' | 'recvonly' | 'inactive' | null {
  const name = decodeLatin1Span(buffer, attr.nameSpan).toLowerCase();
  if (name === 'sendrecv' || name === 'sendonly' || name === 'recvonly' || name === 'inactive') {
    return name;
  }
  return null;
}

export function hasRtcpMux(attributes: readonly SdpAttribute[]): boolean {
  return attributes.some((a) => a.kind === 'rtcp-mux');
}

/** Collect RTP header-extension IDs advertised via SDP `a=extmap`. */
export function collectExtmapIds(
  sessionAttrs: readonly SdpAttribute[],
  mediaAttrs: readonly SdpAttribute[] = [],
): ReadonlySet<number> {
  const ids = new Set<number>()
  for (const attr of [...sessionAttrs, ...mediaAttrs]) {
    if (attr.kind === 'extmap' && attr.extmapId != null) ids.add(attr.extmapId)
  }
  return ids
}

/** Collect RTP payload types mapped to `telephone-event` (DTMF) via SDP rtpmap. */
export function collectTelephoneEventPayloadTypes(
  buffer: Uint8Array,
  sessionAttrs: readonly SdpAttribute[],
  mediaAttrs: readonly SdpAttribute[] = [],
): ReadonlySet<number> {
  const ids = new Set<number>()
  for (const attr of [...sessionAttrs, ...mediaAttrs]) {
    if (attr.kind !== 'preserve') continue
    const name = decodeLatin1Span(buffer, attr.nameSpan).toLowerCase()
    if (name !== 'rtpmap') continue
    const value = decodeLatin1Span(buffer, attr.valueSpan).trim()
    // "101 telephone-event/8000"
    const m = /^(\d+)\s+telephone-event(?:\/|$)/i.exec(value)
    if (!m) continue
    const pt = Number.parseInt(m[1]!, 10)
    if (Number.isInteger(pt) && pt >= 0 && pt <= 127) ids.add(pt)
  }
  return ids
}
