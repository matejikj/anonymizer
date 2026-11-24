/**
 * Extract typed sensitive entities from parsed SDP (step 5).
 */

import type { ByteSpan } from '../sip/types';
import { decodeLatin1Span } from './lines';
import { sdpAddressCategory, sdpEntityKindForAddress } from './hostKind';
import type {
  SdpRedactionPolicy,
  SdpAttribute,
  SdpConnection,
  SdpExtractionResult,
  SdpMappingCategory,
  SdpMedia,
  SdpOrigin,
  SdpSensitiveEntity,
  SdpSession,
} from './types';
import { DEFAULT_SDP_REDACTION_POLICY } from './types';
import { scopeSdpSessionId } from '../../../../mapping/pcapCanonical.ts';

export interface ExtractSdpEntitiesOptions {
  readonly policy?: SdpRedactionPolicy;
}

function spanText(buffer: Uint8Array, span: ByteSpan): string {
  return decodeLatin1Span(buffer, span);
}

function pushEntity(out: SdpSensitiveEntity[], entity: SdpSensitiveEntity): void {
  out.push(entity);
}

function pushAddressEntity(
  out: SdpSensitiveEntity[],
  buffer: Uint8Array,
  span: ByteSpan,
  addrTypeSpan: ByteSpan,
  mediaIndex: number | null,
  field: string,
): void {
  const addressText = spanText(buffer, span);
  const addrTypeText = spanText(buffer, addrTypeSpan);
  const category = sdpAddressCategory(addressText, addrTypeText);
  pushEntity(out, {
    kind: sdpEntityKindForAddress(category),
    span,
    action: 'map',
    canonicalText: addressText.split('/')[0] ?? addressText,
    mediaIndex,
    field,
    mappingCategory: category,
  });
}

function extractConnection(
  out: SdpSensitiveEntity[],
  buffer: Uint8Array,
  conn: SdpConnection,
  mediaIndex: number | null,
  field: string,
): void {
  pushAddressEntity(out, buffer, conn.address, conn.addrType, mediaIndex, field);
}

function extractOrigin(
  out: SdpSensitiveEntity[],
  buffer: Uint8Array,
  origin: SdpOrigin,
): void {
  pushEntity(out, {
    kind: 'origin-username',
    span: origin.username,
    action: 'map',
    canonicalText: spanText(buffer, origin.username),
    mediaIndex: null,
    field: 'o.username',
    mappingCategory: 'sip-token',
  });
  const usernameText = spanText(buffer, origin.username);
  const sessionIdText = spanText(buffer, origin.sessionId);
  // T01 — author/session scope so two origins with the same numeric id stay distinct.
  const scopedSessionId = scopeSdpSessionId(usernameText, sessionIdText);
  pushEntity(out, {
    kind: 'session-id',
    span: origin.sessionId,
    action: 'map',
    canonicalText: scopedSessionId,
    mediaIndex: null,
    field: 'o.session-id',
    mappingCategory: 'sdp-session-id',
  });
  // session-version is not a MappingAuthority identity — deferred modular shift (T01).
  pushEntity(out, {
    kind: 'session-version',
    span: origin.sessionVersion,
    action: 'map',
    canonicalText: spanText(buffer, origin.sessionVersion),
    mediaIndex: null,
    field: 'o.session-version',
    mappingCategory: null,
    sessionIdForVersion: scopedSessionId,
  });
  pushAddressEntity(out, buffer, origin.address, origin.addrType, null, 'o.address');
}

function extractAttributes(
  out: SdpSensitiveEntity[],
  buffer: Uint8Array,
  attributes: readonly SdpAttribute[],
  mediaIndex: number | null,
  policy: SdpRedactionPolicy,
): void {
  for (const attr of attributes) {
    switch (attr.kind) {
      case 'ice-ufrag':
        pushEntity(out, {
          kind: 'ice-ufrag',
          span: attr.valueSpan,
          action: 'redact',
          canonicalText: '',
          mediaIndex,
          field: 'a.ice-ufrag',
          mappingCategory: null,
        });
        break;
      case 'ice-pwd':
        pushEntity(out, {
          kind: 'ice-pwd',
          span: attr.valueSpan,
          action: 'redact',
          canonicalText: '',
          mediaIndex,
          field: 'a.ice-pwd',
          mappingCategory: null,
        });
        break;
      case 'fingerprint':
        if (attr.fingerprint) {
          const action = policy.fingerprint === 'map' ? 'map' : 'redact';
          pushEntity(out, {
            kind: 'fingerprint',
            span: attr.fingerprint.fingerprint,
            action,
            canonicalText: action === 'map' ? spanText(buffer, attr.fingerprint.fingerprint) : '',
            mediaIndex,
            field: 'a.fingerprint',
            mappingCategory: action === 'map' ? 'sip-token' : null,
          });
        }
        break;
      case 'crypto':
        if (attr.crypto) {
          pushEntity(out, {
            kind: 'crypto-key',
            span: attr.crypto.keyParams,
            action: 'redact',
            canonicalText: '',
            mediaIndex,
            field: 'a.crypto',
            mappingCategory: null,
          });
        } else {
          pushEntity(out, {
            kind: 'crypto-key',
            span: attr.valueSpan,
            action: 'redact',
            canonicalText: '',
            mediaIndex,
            field: 'a.crypto',
            mappingCategory: null,
          });
        }
        break;
      case 'candidate':
        if (attr.candidate) {
          pushEntity(out, {
            kind: 'candidate-address',
            span: attr.candidate.address,
            action: 'map',
            canonicalText: normalizeCandidateAddress(spanText(buffer, attr.candidate.address)),
            mediaIndex,
            field: 'a.candidate.address',
            mappingCategory: guessAddressCategory(spanText(buffer, attr.candidate.address)),
          });
          pushEntity(out, {
            kind: 'candidate-port',
            span: attr.candidate.port,
            action: 'map',
            canonicalText: spanText(buffer, attr.candidate.port),
            mediaIndex,
            field: 'a.candidate.port',
            mappingCategory: 'port',
          });
          if (attr.candidate.relatedAddress) {
            pushEntity(out, {
              kind: 'candidate-address',
              span: attr.candidate.relatedAddress,
              action: 'map',
              canonicalText: normalizeCandidateAddress(spanText(buffer, attr.candidate.relatedAddress)),
              mediaIndex,
              field: 'a.candidate.raddr',
              mappingCategory: guessAddressCategory(spanText(buffer, attr.candidate.relatedAddress)),
            });
          }
          if (attr.candidate.relatedPort) {
            pushEntity(out, {
              kind: 'candidate-port',
              span: attr.candidate.relatedPort,
              action: 'map',
              canonicalText: spanText(buffer, attr.candidate.relatedPort),
              mediaIndex,
              field: 'a.candidate.rport',
              mappingCategory: 'port',
            });
          }
        }
        break;
      case 'remote-candidates':
        for (const remote of attr.remoteCandidates) {
          pushEntity(out, {
            kind: 'candidate-address',
            span: remote.address,
            action: 'map',
            canonicalText: normalizeCandidateAddress(spanText(buffer, remote.address)),
            mediaIndex,
            field: 'a.remote-candidates.address',
            mappingCategory: guessAddressCategory(spanText(buffer, remote.address)),
          });
          pushEntity(out, {
            kind: 'candidate-port',
            span: remote.port,
            action: 'map',
            canonicalText: spanText(buffer, remote.port),
            mediaIndex,
            field: 'a.remote-candidates.port',
            mappingCategory: 'port',
          });
        }
        break;
      case 'rtcp':
        if (attr.rtcpPort) {
          pushEntity(out, {
            kind: 'rtcp-port',
            span: attr.rtcpPort,
            action: 'map',
            canonicalText: spanText(buffer, attr.rtcpPort),
            mediaIndex,
            field: 'a.rtcp',
            mappingCategory: 'port',
          });
        }
        if (attr.rtcpAddress && attr.rtcpAddrType) {
          pushAddressEntity(
            out,
            buffer,
            attr.rtcpAddress,
            attr.rtcpAddrType,
            mediaIndex,
            'a.rtcp.address',
          );
        }
        break;
      case 'direction':
      case 'rtcp-mux':
      case 'preserve':
        break;
      case 'generic':
      default:
        if (attr.valueSpan.length > 0) {
          pushEntity(out, {
            kind: 'unknown-attribute',
            span: attr.valueSpan,
            action: 'redact',
            canonicalText: '',
            mediaIndex,
            field: `a.${spanText(buffer, attr.nameSpan)}`,
            mappingCategory: null,
          });
        }
        break;
    }
  }
}

function normalizeCandidateAddress(text: string): string {
  if (text.startsWith('[') && text.endsWith(']')) return text.slice(1, -1);
  return text;
}

function guessAddressCategory(text: string): SdpMappingCategory {
  const normalized = normalizeCandidateAddress(text);
  return sdpAddressCategory(normalized, normalized.includes(':') ? 'IP6' : 'IP4');
}

function extractMediaSection(
  out: SdpSensitiveEntity[],
  buffer: Uint8Array,
  media: SdpMedia,
  mediaIndex: number,
  policy: SdpRedactionPolicy,
): void {
  pushEntity(out, {
    kind: 'port',
    span: media.port,
    action: 'map',
    canonicalText: spanText(buffer, media.port),
    mediaIndex,
    field: 'm.port',
    mappingCategory: 'port',
  });

  if (media.connection) {
    extractConnection(out, buffer, media.connection, mediaIndex, 'm.connection');
  }

  extractAttributes(out, buffer, media.attributes, mediaIndex, policy);
}

export function extractSdpEntities(
  session: SdpSession,
  buffer: Uint8Array,
  options: ExtractSdpEntitiesOptions = {},
): SdpExtractionResult {
  const policy = options.policy ?? DEFAULT_SDP_REDACTION_POLICY;
  const entities: SdpSensitiveEntity[] = [];
  const issues: string[] = [];

  if (session.origin) extractOrigin(entities, buffer, session.origin);
  else issues.push('missing-o-line');

  if (session.sessionConnection) {
    extractConnection(entities, buffer, session.sessionConnection, null, 'session.connection');
  }

  // b= (bandwidth) and t= (timing) are numeric-only by the SDP grammar itself, so — unlike
  // s= (session name), which is arbitrary free text and can legitimately carry something
  // sensitive (a real session/meeting title) — they can never carry identifying content and
  // are safe to preserve. Same reasoning as i=/u=/e=/p=/k=, which stay redacted (free text,
  // URI, email, phone number, key).
  const PRESERVED_METADATA_TYPES = new Set(['b', 't']);
  for (const meta of session.metadataLines) {
    if (meta.valueSpan.length <= 0) continue;
    if (PRESERVED_METADATA_TYPES.has(meta.type)) continue;
    pushEntity(entities, {
      kind: 'metadata-text',
      span: meta.valueSpan,
      action: 'redact',
      canonicalText: '',
      mediaIndex: null,
      field: `${meta.type}.value`,
      mappingCategory: null,
    });
  }

  extractAttributes(entities, buffer, session.sessionAttributes, null, policy);

  session.media.forEach((media, index) => {
    extractMediaSection(entities, buffer, media, index, policy);
  });

  if (session.media.length === 0) issues.push('missing-m-section');

  return { entities, issues };
}
