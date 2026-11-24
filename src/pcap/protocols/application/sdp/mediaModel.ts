/**
 * Build normalized media endpoints and RTP/RTCP flow keys from parsed SDP.
 */

import type { ByteSpan } from '../sip/types';
import { hasRtcpMux, readAttributeDirection, collectExtmapIds, collectTelephoneEventPayloadTypes } from './attributes';
import { decodeLatin1Span } from './lines';
import { normalizeSdpAddress } from './hostKind';
import type {
  SdpFlowKey,
  SdpMedia,
  SdpMediaDirection,
  SdpMediaEndpoint,
  SdpSession,
} from './types';

export interface SdpMediaContext {
  readonly callId?: string | null;
}

function spanText(buffer: Uint8Array, span: ByteSpan): string {
  return decodeLatin1Span(buffer, span);
}

function parsePort(buffer: Uint8Array, span: ByteSpan): number | null {
  const text = spanText(buffer, span);
  const n = Number.parseInt(text, 10);
  return Number.isFinite(n) ? n : null;
}

function resolveConnectionAddress(
  session: SdpSession,
  media: SdpMedia,
  buffer: Uint8Array,
): { readonly address: string; readonly addrType: string } | null {
  const conn = media.connection ?? session.sessionConnection ?? (
    session.origin
      ? {
          span: session.origin.address,
          netType: session.origin.netType,
          addrType: session.origin.addrType,
          address: session.origin.address,
        }
      : null
  );

  if (!conn) return null;

  const addrType = spanText(buffer, conn.addrType);
  const address = normalizeSdpAddress(spanText(buffer, conn.address));
  return { address, addrType };
}

function resolveDirection(media: SdpMedia, buffer: Uint8Array): SdpMediaDirection {
  for (const attr of media.attributes) {
    const dir = readAttributeDirection(buffer, attr);
    if (dir) return dir;
  }
  return 'unknown';
}

function resolveRtcpPort(
  media: SdpMedia,
  buffer: Uint8Array,
  rtpPort: number,
): number | null {
  // RFC 5761 — multiplexed RTCP shares the RTP port.
  if (hasRtcpMux(media.attributes)) return rtpPort

  // Explicit SDP a=rtcp:<port> [nettype addrtype address]
  for (const attr of media.attributes) {
    if (attr.kind === 'rtcp' && attr.rtcpPort) {
      const port = parsePort(buffer, attr.rtcpPort)
      if (port !== null) return port
    }
  }

  // m=<media> <port>/<port-count> with port-count=2 implies RTP + next RTCP (RFC 4566).
  const portCount = media.portCount ? parsePort(buffer, media.portCount) : null
  if (portCount === 2) return rtpPort + 1

  // Enterprise step 6: do NOT invent p+1 when SDP gives no RTCP signal.
  // Media-flow detection / actual packets remain authoritative.
  return null
}

function flowKey(protocol: 'rtp' | 'rtcp', ip: string, port: number): SdpFlowKey {
  return { protocol, ip, port };
}

function addCandidateFlowKeys(
  out: SdpFlowKey[],
  media: SdpMedia,
  buffer: Uint8Array,
): void {
  for (const attr of media.attributes) {
    if (attr.kind !== 'candidate' || !attr.candidate) continue;
    const ip = normalizeSdpAddress(spanText(buffer, attr.candidate.address));
    const port = parsePort(buffer, attr.candidate.port);
    if (port === null) continue;
    const component = spanText(buffer, attr.candidate.componentId);
    const protocol: 'rtp' | 'rtcp' = component === '2' ? 'rtcp' : 'rtp';
    out.push(flowKey(protocol, ip, port));
  }
}

export function buildSdpMediaEndpoints(
  session: SdpSession,
  buffer: Uint8Array,
  context: SdpMediaContext = {},
): readonly SdpMediaEndpoint[] {
  const endpoints: SdpMediaEndpoint[] = [];

  session.media.forEach((media, mediaIndex) => {
    const conn = resolveConnectionAddress(session, media, buffer);
    const rtpPort = parsePort(buffer, media.port);
    if (!conn || rtpPort === null) return;

    const rtcpPort = resolveRtcpPort(media, buffer, rtpPort);
    const flowKeys: SdpFlowKey[] = [
      flowKey('rtp', conn.address, rtpPort),
    ];
    if (rtcpPort !== null) {
      flowKeys.push(flowKey('rtcp', conn.address, rtcpPort));
    }
    addCandidateFlowKeys(flowKeys, media, buffer);

    const headerExtensionIds = [...collectExtmapIds(session.sessionAttributes, media.attributes)]
    const telephoneEventPayloadTypes = [
      ...collectTelephoneEventPayloadTypes(buffer, session.sessionAttributes, media.attributes),
    ]

    endpoints.push({
      mediaIndex,
      mediaType: spanText(buffer, media.mediaType),
      protocol: spanText(buffer, media.protocol),
      payloadTypes: media.payloadTypes.map((pt) => spanText(buffer, pt)),
      address: conn.address,
      port: rtpPort,
      rtcpPort,
      direction: resolveDirection(media, buffer),
      callId: context.callId ?? null,
      flowKeys: dedupeFlowKeys(flowKeys),
      headerExtensionIds,
      telephoneEventPayloadTypes,
    });
  });

  return endpoints;
}

function dedupeFlowKeys(keys: readonly SdpFlowKey[]): readonly SdpFlowKey[] {
  const seen = new Set<string>();
  const out: SdpFlowKey[] = [];
  for (const key of keys) {
    const id = `${key.protocol}:${key.ip}:${key.port}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(key);
  }
  return out;
}

export function collectFlowKeys(endpoints: readonly SdpMediaEndpoint[]): readonly SdpFlowKey[] {
  const out: SdpFlowKey[] = [];
  for (const ep of endpoints) out.push(...ep.flowKeys);
  return dedupeFlowKeys(out);
}
