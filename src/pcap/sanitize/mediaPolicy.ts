/**
 * Apply VoIP media policy to classified RTP/RTCP packets (step 8 / CF-03).
 * telephone-event (DTMF) is SECRET/MEDIA — never preserve-unsafe.
 */

import type { MediaPacketClassification } from '../discovery/mediaFlowIndex';
import type { LayerCoverage, SanitizationPolicy, VoipMediaPolicy } from './types';
import { isPreserveUnsafeMediaPolicy, isStripPayloadMediaPolicy } from './types';
import { isTelephoneEventPayload, TELEPHONE_EVENT_ISSUE } from './telephoneEvent';

export interface MediaPolicyResult {
  readonly drop: boolean;
  readonly protocol: string;
  readonly status: LayerCoverage['status'];
  readonly telephoneEvent?: boolean;
}

export function applyVoipMediaPolicy(
  classification: MediaPacketClassification,
  policy: SanitizationPolicy,
  payloadOffset: number,
  payloadLength: number,
  coverage: LayerCoverage[],
  issues: string[],
  payload?: Uint8Array,
): MediaPolicyResult {
  const mediaPolicy: VoipMediaPolicy = policy.mediaPolicy;
  const protocol = classification.kind === 'encrypted-media' ? 'srtp' : classification.kind;
  const confidence = classification.confidence;

  const dtmfPts = classification.entry?.telephoneEventPayloadTypes ?? [];
  const isDtmf =
    (classification.kind === 'rtp' || classification.kind === 'encrypted-media')
    && payload !== undefined
    && isTelephoneEventPayload(payload, payloadOffset, payloadLength, dtmfPts);

  if (isDtmf) {
    issues.push(TELEPHONE_EVENT_ISSUE);
    // high-privacy drop: remove whole DTMF packet; diagnostic strip-payload: mask digits.
    if (mediaPolicy === 'drop') {
      coverage.push({
        protocol: 'rtp-telephone-event',
        offset: payloadOffset,
        length: payloadLength,
        status: 'covered',
      });
      issues.push('RTP telephone-event dropped (mediaPolicy=drop; SECRET)');
      return { drop: true, protocol: 'rtp-telephone-event', status: 'covered', telephoneEvent: true };
    }
    // Never preserve-unsafe for DTMF — force strip/mask path.
    coverage.push({
      protocol: 'rtp-telephone-event',
      offset: payloadOffset,
      length: payloadLength,
      status: 'redacted',
    });
    issues.push('RTP telephone-event masked (SECRET/MEDIA)');
    return { drop: false, protocol: 'rtp', status: 'redacted', telephoneEvent: true };
  }

  if (mediaPolicy === 'drop') {
    // Confirmed RTP/RTCP/SRTP: remove the whole packet from export.
    if (confidence === 'confirmed' || classification.kind === 'encrypted-media') {
      coverage.push({
        protocol,
        offset: payloadOffset,
        length: payloadLength,
        status: 'covered',
      });
      issues.push(
        classification.kind === 'encrypted-media'
          ? 'SRTP packet dropped (mediaPolicy=drop)'
          : `${protocol.toUpperCase()} packet dropped (mediaPolicy=drop)`,
      );
      return { drop: true, protocol, status: 'covered' };
    }

    // Suspected media: keep L3/L4 headers, truncate payload via CF-09 (unsupported).
    coverage.push({
      protocol,
      offset: payloadOffset,
      length: payloadLength,
      status: 'unsupported',
    });
    issues.push(`${protocol.toUpperCase()} suspected media truncated (mediaPolicy=drop)`);
    return { drop: false, protocol, status: 'unsupported' };
  }

  // T68 — fixed levels never select preserve-unsafe; if a caller still passes it,
  // fail-closed to strip-payload (length-preserving mask) instead of exporting voice.
  if (isStripPayloadMediaPolicy(mediaPolicy) || isPreserveUnsafeMediaPolicy(mediaPolicy)) {
    coverage.push({
      protocol,
      offset: payloadOffset,
      length: payloadLength,
      status: 'redacted',
    });
    issues.push(
      isPreserveUnsafeMediaPolicy(mediaPolicy)
        ? `${protocol.toUpperCase()} media strip-payload (T68: preserve-unsafe remapped); headers/stats preserved`
        : `${protocol.toUpperCase()} media strip-payload (mediaPolicy=strip-payload); headers/stats preserved`,
    );
    return { drop: false, protocol, status: 'redacted' };
  }

  if (classification.kind === 'encrypted-media') {
    coverage.push({
      protocol: 'srtp',
      offset: payloadOffset,
      length: payloadLength,
      status: 'encrypted',
    });
    return { drop: false, protocol: 'srtp', status: 'encrypted' };
  }

  coverage.push({
    protocol,
    offset: payloadOffset,
    length: payloadLength,
    status: 'unsupported',
  });
  return { drop: false, protocol, status: 'unsupported' };
}

/** TLS record shape check — not proof of encrypted application data (CF-10). */
export function looksLikeTlsRecord(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 5) return false;
  const contentType = data[offset]!;
  if (contentType !== 0x16 && contentType !== 0x17 && contentType !== 0x14 && contentType !== 0x15) {
    return false;
  }
  return data[offset + 1] === 0x03 && data[offset + 2]! >= 0x00 && data[offset + 2]! <= 0x04;
}
