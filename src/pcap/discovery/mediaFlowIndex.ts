/**
 * Capture-level VoIP media flow index (step 8 / CF-03).
 *
 * Combines SDP-derived endpoints with UDP conversation evidence (SSRC / sequence)
 * so mediaPolicy can drop confirmed RTP/RTCP even when SDP is missing or arrives later.
 */

import type { SipMessage } from '../protocols/application/sip/types';
import { buildSdpSessionBundle } from '../protocols/application/sdp/attach';
import { decodeLatin1Span } from '../protocols/application/sdp/lines';
import type { SdpFlowKey, SdpMedia, SdpMediaEndpoint, SdpSession, SdpSessionBundle } from '../protocols/application/sdp/types';
import {
  detectMediaShape,
  looksLikeRtcpPayload,
  looksLikeRtpPayload,
  parseRtpHeader,
  type MediaShapeKind,
} from '../protocols/application/rtp/classify';
import { SIP_PORT, SIP_TLS_PORT } from '../protocols/application/sip/classify';

export interface MediaFlowEntry {
  readonly protocol: 'rtp' | 'rtcp';
  readonly ip: string;
  readonly port: number;
  readonly encrypted: boolean;
  readonly payloadTypes: readonly string[];
  readonly callId: string | null;
  /** SDP `a=extmap` IDs for this media section (empty when unknown). */
  readonly headerExtensionIds: readonly number[];
  /** SDP telephone-event payload types (DTMF) — SECRET/MEDIA, never safe. */
  readonly telephoneEventPayloadTypes: readonly number[];
}

export type MediaConfidence = 'confirmed' | 'suspected';

export type MediaPacketClassification =
  | { readonly kind: 'rtp'; readonly confidence: MediaConfidence; readonly entry: MediaFlowEntry | null }
  | { readonly kind: 'rtcp'; readonly confidence: MediaConfidence; readonly entry: MediaFlowEntry | null }
  | { readonly kind: 'encrypted-media'; readonly confidence: MediaConfidence; readonly entry: MediaFlowEntry | null };

export interface ClassifyMediaPacketInput {
  readonly srcIp: string;
  readonly dstIp: string;
  readonly srcPort: number;
  readonly dstPort: number;
  readonly payload: Uint8Array;
  readonly payloadOffset: number;
  readonly payloadLength: number;
}

const MAX_FLOW_ENTRIES = 4096;
const MAX_CONVERSATIONS = 4096;
const CONFIRMED_SAME_SSRC_HITS = 3;
const CONFIRMED_SEQ_ADVANCES = 1;

interface SsrcObservation {
  count: number;
  lastSeq: number | null;
  advances: number;
}

interface ConversationObservation {
  rtpHits: number;
  rtcpHits: number;
  ssrcs: Map<number, SsrcObservation>;
}

function flowMapKey(protocol: 'rtp' | 'rtcp', ip: string, port: number): string {
  return `${protocol}:${ip.toLowerCase()}:${port}`;
}

function conversationKey(input: ClassifyMediaPacketInput): string {
  const a = `${input.srcIp.toLowerCase()}:${input.srcPort}`;
  const b = `${input.dstIp.toLowerCase()}:${input.dstPort}`;
  return a < b ? `${a}|${b}` : `${b}|${a}`;
}

function isEncryptedMediaProtocol(protocolText: string): boolean {
  const upper = protocolText.toUpperCase();
  return upper.includes('SAVP') || upper.includes('SRTP') || upper.includes('/TLS/');
}

function mediaHasCrypto(media: SdpMedia, buffer: Uint8Array): boolean {
  for (const attr of media.attributes) {
    if (attr.kind === 'crypto') return true;
  }
  void buffer;
  return false;
}

function endpointEncrypted(endpoint: SdpMediaEndpoint, session: SdpSession, buffer: Uint8Array): boolean {
  if (isEncryptedMediaProtocol(endpoint.protocol)) return true;
  const media = session.media[endpoint.mediaIndex];
  if (!media) return false;
  return mediaHasCrypto(media, buffer);
}

function seqAdvanced(prev: number, next: number): boolean {
  const delta = (next - prev) & 0xffff;
  return delta > 0 && delta < 3000;
}

function isSipSignalingPort(port: number): boolean {
  return port === SIP_PORT || port === SIP_TLS_PORT;
}

function mergeUniqueNumbers(
  a: readonly number[],
  b: readonly number[],
): readonly number[] {
  if (b.length === 0) return a
  if (a.length === 0) return b
  const set = new Set(a)
  let changed = false
  for (const n of b) {
    if (!set.has(n)) {
      set.add(n)
      changed = true
    }
  }
  return changed ? [...set] : a
}

export class MediaFlowIndex {
  private readonly _flows = new Map<string, MediaFlowEntry>();
  private readonly _conversations = new Map<string, ConversationObservation>();
  private _overflow = false;

  get size(): number {
    return this._flows.size;
  }

  get overflow(): boolean {
    return this._overflow;
  }

  entries(): readonly MediaFlowEntry[] {
    return [...this._flows.values()];
  }

  /**
   * SDP `m=` registered this IP:port as media and advertised a t38 fmt
   * (`m=image … UDPTL t38`). Used to gate T.38/UDPTL before weak wire sniff.
   */
  isLikelyT38Endpoint(ip: string, port: number): boolean {
    const entry = this._flows.get(flowMapKey('rtp', ip, port));
    if (!entry) return false;
    return entry.payloadTypes.some((pt) => /t38/i.test(pt));
  }

  registerBundle(bundle: SdpSessionBundle, buffer: Uint8Array): void {
    for (const endpoint of bundle.endpoints) {
      const encrypted = endpointEncrypted(endpoint, bundle.session, buffer);
      this.registerEndpoint(endpoint, encrypted);
    }
  }

  registerFromSipMessage(message: SipMessage, buffer: Uint8Array): void {
    const attached = buildSdpSessionBundle(message, buffer);
    if (attached.kind !== 'parsed' || attached.sdp.kind !== 'complete' || !attached.bundle) return;
    this.registerBundle(attached.bundle, buffer);
  }

  private registerEndpoint(endpoint: SdpMediaEndpoint, encrypted: boolean): void {
    for (const key of endpoint.flowKeys) {
      this.registerFlowKey(
        key,
        encrypted,
        endpoint.payloadTypes,
        endpoint.callId,
        endpoint.headerExtensionIds,
        endpoint.telephoneEventPayloadTypes,
      );
    }
  }

  private registerFlowKey(
    key: SdpFlowKey,
    encrypted: boolean,
    payloadTypes: readonly string[],
    callId: string | null,
    headerExtensionIds: readonly number[] = [],
    telephoneEventPayloadTypes: readonly number[] = [],
  ): void {
    if (this._flows.size >= MAX_FLOW_ENTRIES) {
      this._overflow = true;
      return;
    }
    const id = flowMapKey(key.protocol, key.ip, key.port);
    const existing = this._flows.get(id);
    if (existing) {
      const mergedIds = mergeUniqueNumbers(existing.headerExtensionIds, headerExtensionIds);
      const mergedDtmf = mergeUniqueNumbers(
        existing.telephoneEventPayloadTypes,
        telephoneEventPayloadTypes,
      );
      if (
        existing.encrypted
        || encrypted
        || mergedIds !== existing.headerExtensionIds
        || mergedDtmf !== existing.telephoneEventPayloadTypes
      ) {
        this._flows.set(id, {
          ...existing,
          encrypted: existing.encrypted || encrypted,
          headerExtensionIds: mergedIds,
          telephoneEventPayloadTypes: mergedDtmf,
        });
      }
      return;
    }
    this._flows.set(id, {
      protocol: key.protocol,
      ip: key.ip,
      port: key.port,
      encrypted,
      payloadTypes: payloadTypes,
      callId,
      headerExtensionIds,
      telephoneEventPayloadTypes,
    });
  }

  /**
   * Classify a UDP payload as media.
   * Prefer SDP endpoint + shape; otherwise use conversation evidence (CF-03).
   */
  classify(input: ClassifyMediaPacketInput): MediaPacketClassification | null {
    const sdpHit = this.classifyFromSdp(input);
    if (sdpHit) return sdpHit;

    // SIP signaling ports are never legitimate RTP/RTCP media ports per SDP; a flow already
    // tied to SIP must not be reclassified as media by payload shape alone (step 4).
    if (isSipSignalingPort(input.srcPort) || isSipSignalingPort(input.dstPort)) {
      return null;
    }

    const shape = detectMediaShape(input.payload, input.payloadOffset, input.payloadLength);
    if (!shape) return null;

    this.observeShape(input, shape);
    // A single payload-shaped packet with no corroborating flow evidence (SDP endpoint,
    // repeated SSRC, or advancing sequence numbers) is weaker signal than a confirmed
    // multi-packet or SDP-backed match, but it must still surface as *some* classification:
    // gating it out entirely regresses the first packet of every genuine no-SDP RTP/RTCP
    // stream (confirmed against dt.pcap's mandatory 3250 RTP / 22 RTCP regression table —
    // requiring evidence dropped RTCP to 21). Downstream disposition already treats
    // 'suspected' conservatively under mediaPolicy=drop (truncate, not drop-as-confirmed).
    const confidence: MediaConfidence = this.hasFlowEvidence(input, shape) ? 'confirmed' : 'suspected';
    return { kind: shape, confidence, entry: null };
  }

  private classifyFromSdp(input: ClassifyMediaPacketInput): MediaPacketClassification | null {
    // PF-11: _flows is already keyed by exactly `${protocol}:${ip}:${port}` (flowMapKey), so
    // a packet can only ever match at most one of its own src/dst endpoints per protocol —
    // four direct Map lookups replace what used to be a linear scan over every registered
    // flow (up to MAX_FLOW_ENTRIES = 4096) for every UDP packet with a payload.
    const rtpEntries: MediaFlowEntry[] = [];
    const rtcpEntries: MediaFlowEntry[] = [];

    for (const protocol of ['rtp', 'rtcp'] as const) {
      const bucket = protocol === 'rtp' ? rtpEntries : rtcpEntries;
      const bySrc = this._flows.get(flowMapKey(protocol, input.srcIp, input.srcPort));
      if (bySrc) bucket.push(bySrc);
      const byDst = this._flows.get(flowMapKey(protocol, input.dstIp, input.dstPort));
      if (byDst && byDst !== bySrc) bucket.push(byDst);
    }

    if (rtpEntries.length === 0 && rtcpEntries.length === 0) return null;

    const isRtcpShape = looksLikeRtcpPayload(input.payload, input.payloadOffset, input.payloadLength);
    const isRtpShape = rtpEntries.some((entry) => looksLikeRtpPayload(
      input.payload,
      input.payloadOffset,
      input.payloadLength,
      entry.payloadTypes,
    ));

    if (isRtcpShape && rtcpEntries.length > 0) {
      this.observeShape(input, 'rtcp');
      return this.finish(rtcpEntries[0]!, 'rtcp');
    }

    if (isRtpShape && rtpEntries.length > 0) {
      this.observeShape(input, 'rtp');
      return this.finish(rtpEntries[0]!, 'rtp');
    }

    return null;
  }

  private observeShape(input: ClassifyMediaPacketInput, shape: MediaShapeKind): void {
    const key = conversationKey(input);
    let obs = this._conversations.get(key);
    if (!obs) {
      if (this._conversations.size >= MAX_CONVERSATIONS) {
        this._overflow = true;
        return;
      }
      obs = { rtpHits: 0, rtcpHits: 0, ssrcs: new Map() };
      this._conversations.set(key, obs);
    }

    if (shape === 'rtcp') {
      obs.rtcpHits += 1;
      return;
    }

    obs.rtpHits += 1;
    const header = parseRtpHeader(input.payload, input.payloadOffset, input.payloadLength);
    if (!header) return;

    let ssrcObs = obs.ssrcs.get(header.ssrc);
    if (!ssrcObs) {
      ssrcObs = { count: 0, lastSeq: null, advances: 0 };
      obs.ssrcs.set(header.ssrc, ssrcObs);
    }
    ssrcObs.count += 1;
    if (ssrcObs.lastSeq !== null && seqAdvanced(ssrcObs.lastSeq, header.sequence)) {
      ssrcObs.advances += 1;
    }
    ssrcObs.lastSeq = header.sequence;
  }

  private hasFlowEvidence(input: ClassifyMediaPacketInput, shape: MediaShapeKind): boolean {
    const obs = this._conversations.get(conversationKey(input));
    if (!obs) return false;

    if (shape === 'rtcp') {
      return obs.rtcpHits >= 2 || obs.rtpHits >= 1;
    }

    for (const ssrcObs of obs.ssrcs.values()) {
      if (ssrcObs.count >= CONFIRMED_SAME_SSRC_HITS) return true;
      if (ssrcObs.advances >= CONFIRMED_SEQ_ADVANCES && ssrcObs.count >= 2) return true;
    }
    return false;
  }

  private finish(
    entry: MediaFlowEntry,
    forceKind?: 'rtp' | 'rtcp',
  ): MediaPacketClassification {
    if (entry.encrypted) {
      return { kind: 'encrypted-media', confidence: 'confirmed', entry };
    }
    const kind = forceKind ?? entry.protocol;
    return kind === 'rtcp'
      ? { kind: 'rtcp', confidence: 'confirmed', entry }
      : { kind: 'rtp', confidence: 'confirmed', entry };
  }
}

/** Detect SRTP/DTLS-style SDP media from raw protocol line text. */
export function sdpMediaProtocolText(media: SdpMedia, buffer: Uint8Array): string {
  return decodeLatin1Span(buffer, media.protocol);
}
