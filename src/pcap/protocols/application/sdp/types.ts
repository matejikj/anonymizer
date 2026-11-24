/**
 * Byte-oriented SDP session model (step 5).
 */

import type { ByteSpan } from '../sip/types';

export interface SdpOrigin {
  readonly span: ByteSpan;
  readonly username: ByteSpan;
  readonly sessionId: ByteSpan;
  readonly sessionVersion: ByteSpan;
  readonly netType: ByteSpan;
  readonly addrType: ByteSpan;
  readonly address: ByteSpan;
}

export interface SdpConnection {
  readonly span: ByteSpan;
  readonly netType: ByteSpan;
  readonly addrType: ByteSpan;
  readonly address: ByteSpan;
}

export type SdpAttributeKind =
  | 'rtcp'
  | 'candidate'
  | 'remote-candidates'
  | 'ice-ufrag'
  | 'ice-pwd'
  | 'fingerprint'
  | 'crypto'
  | 'direction'
  | 'rtcp-mux'
  | 'extmap'
  /** Non-identifying media/codec/negotiation attributes (rtpmap, fmtp, X-nat, …) — passthrough. */
  | 'preserve'
  | 'generic';

export interface SdpCandidate {
  readonly foundation: ByteSpan;
  readonly componentId: ByteSpan;
  readonly transport: ByteSpan;
  readonly priority: ByteSpan;
  readonly address: ByteSpan;
  readonly port: ByteSpan;
  readonly typ: ByteSpan | null;
  readonly relatedAddress: ByteSpan | null;
  readonly relatedPort: ByteSpan | null;
}

export interface SdpRemoteCandidate {
  readonly componentId: ByteSpan;
  readonly address: ByteSpan;
  readonly port: ByteSpan;
}

export interface SdpFingerprint {
  readonly hashFunc: ByteSpan;
  readonly fingerprint: ByteSpan;
}

export interface SdpCrypto {
  readonly tag: ByteSpan;
  readonly suite: ByteSpan;
  readonly keyParams: ByteSpan;
}

export interface SdpAttribute {
  readonly span: ByteSpan;
  readonly kind: SdpAttributeKind;
  readonly nameSpan: ByteSpan;
  readonly valueSpan: ByteSpan;
  readonly candidate: SdpCandidate | null;
  readonly remoteCandidates: readonly SdpRemoteCandidate[];
  readonly fingerprint: SdpFingerprint | null;
  readonly crypto: SdpCrypto | null;
  readonly rtcpPort: ByteSpan | null;
  readonly rtcpAddress: ByteSpan | null;
  readonly rtcpAddrType: ByteSpan | null;
  /** RTP header extension ID from `a=extmap:<id> ...` (one-byte: 1–14, two-byte: 1–255). */
  readonly extmapId: number | null;
  readonly extmapUri: ByteSpan | null;
}

export interface SdpMedia {
  readonly span: ByteSpan;
  readonly mediaType: ByteSpan;
  readonly port: ByteSpan;
  readonly portCount: ByteSpan | null;
  readonly protocol: ByteSpan;
  readonly payloadTypes: readonly ByteSpan[];
  readonly connection: SdpConnection | null;
  readonly attributes: readonly SdpAttribute[];
}

/** Typed SDP lines that are not structurally mapped but may carry PII/credentials (CF-08). */
export interface SdpMetadataLine {
  readonly type: string;
  readonly valueSpan: ByteSpan;
}

export interface SdpSession {
  readonly span: ByteSpan;
  readonly version: ByteSpan | null;
  readonly origin: SdpOrigin | null;
  readonly sessionConnection: SdpConnection | null;
  readonly sessionAttributes: readonly SdpAttribute[];
  readonly media: readonly SdpMedia[];
  readonly metadataLines: readonly SdpMetadataLine[];
}

export interface SdpParseDiagnostics {
  readonly lineCount: number;
  readonly mediaSectionCount: number;
  readonly issues: readonly string[];
}

export type SdpParseResult =
  | { readonly kind: 'complete'; readonly session: SdpSession; readonly diagnostics: SdpParseDiagnostics }
  | { readonly kind: 'malformed'; readonly reason: string; readonly diagnostics: SdpParseDiagnostics }
  | { readonly kind: 'not-sdp'; readonly reason: string; readonly diagnostics: SdpParseDiagnostics };

export type SdpMediaDirection = 'sendrecv' | 'sendonly' | 'recvonly' | 'inactive' | 'unknown';

export interface SdpFlowKey {
  readonly protocol: 'rtp' | 'rtcp';
  readonly ip: string;
  readonly port: number;
}

export interface SdpMediaEndpoint {
  readonly mediaIndex: number;
  readonly mediaType: string;
  readonly protocol: string;
  readonly payloadTypes: readonly string[];
  readonly address: string;
  readonly port: number;
  readonly rtcpPort: number | null;
  readonly direction: SdpMediaDirection;
  readonly callId: string | null;
  readonly flowKeys: readonly SdpFlowKey[];
  /** SDP `a=extmap` IDs (session + media). */
  readonly headerExtensionIds: readonly number[];
  /** SDP `a=rtpmap` payload types for telephone-event (DTMF). */
  readonly telephoneEventPayloadTypes: readonly number[];
}

export interface SdpSessionBundle {
  readonly session: SdpSession;
  readonly endpoints: readonly SdpMediaEndpoint[];
  readonly callId: string | null;
}

export type SdpEntityKind =
  | 'origin-username'
  | 'session-id'
  | 'session-version'
  | 'ipv4'
  | 'ipv6'
  | 'host'
  | 'port'
  | 'payload-type'
  | 'ice-ufrag'
  | 'ice-pwd'
  | 'fingerprint'
  | 'crypto-key'
  | 'candidate-address'
  | 'candidate-port'
  | 'rtcp-port'
  | 'metadata-text'
  | 'unknown-attribute';

export type SdpEntityAction = 'map' | 'redact' | 'allow';

/**
 * Identity categories used by SDP map ops.
 * `sdp-session-id` is the o= session-id digit string (T01). session-version is not an
 * identity — it uses {@link SdpSensitiveEntity.sessionIdForVersion} + modular shift.
 */
export type SdpMappingCategory =
  | 'ipv4'
  | 'ipv6'
  | 'hostname'
  | 'port'
  | 'sip-token'
  | 'sdp-session-id';

export interface SdpSensitiveEntity {
  readonly kind: SdpEntityKind;
  readonly span: ByteSpan;
  readonly action: SdpEntityAction;
  readonly canonicalText: string;
  readonly mediaIndex: number | null;
  readonly field: string;
  readonly mappingCategory: SdpMappingCategory | null;
  /**
   * For `session-version` ops: original session-id digit text from the same `o=` line.
   * Plan path derives the shifted version from the mapped session-id alias (T01).
   */
  readonly sessionIdForVersion?: string;
}

export interface SdpExtractionResult {
  readonly entities: readonly SdpSensitiveEntity[];
  readonly issues: readonly string[];
}

export type SdpFingerprintPolicy = 'map' | 'redact';

export interface SdpRedactionPolicy {
  readonly fingerprint: SdpFingerprintPolicy;
}

export const DEFAULT_SDP_REDACTION_POLICY: SdpRedactionPolicy = {
  fingerprint: 'redact',
};
