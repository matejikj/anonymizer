/**
 * CF-08 — explicit SIP body disposition for fail-closed coverage and redaction.
 */

import type { ByteSpan, SipMessage } from './types';
import {
  evaluateAttachedSdpSafety,
  isSdpContentType,
  sipMessageContentType,
} from '../sdp/attach';
import { looksLikeRadioProtocolBody, parseRadioProtocolBody } from './radioProtocolBody'
import {
  looksLikeDtmfRelayBody,
  looksLikeDialogInfoBody,
  looksLikeIsupBody,
  looksLikeMcpttBody,
  looksLikeSipfragBody,
} from './mcpttBody'
import { looksLikeCstaContentType } from '../csta/xmlPlan'
import {
  looksLikePidfContentType,
  looksLikePidfXmlText,
  looksLikeLostContentType,
  looksLikeLostXmlText,
} from '../location/index.ts'
import { isMultipartContentType } from './multipartBody'

export type SipBodyDecisionKind =
  | 'empty'
  | 'structured-sanitized'
  | 'structured-radio-protocol'
  | 'structured-mcptt'
  | 'structured-dtmf-relay'
  | 'structured-dialog-info'
  | 'structured-sipfrag'
  | 'structured-isup'
  | 'structured-csta'
  | 'structured-pidf'
  | 'structured-lost'
  | 'structured-multipart'
  | 'fully-redacted'
  | 'unsupported'
  | 'malformed'

export interface SipBodyDecision {
  readonly kind: SipBodyDecisionKind;
  readonly reason: string;
  readonly bodySpan: ByteSpan | null;
}

function normalizeContentEncoding(value: string): string {
  return value.trim().split(';')[0]?.trim().toLowerCase() ?? '';
}

export function sipMessageContentEncoding(message: SipMessage): string | null {
  for (const header of message.headers) {
    if (header.canonicalNameText === 'content-encoding') {
      return normalizeContentEncoding(header.valueText);
    }
  }
  return null;
}

/**
 * Decide how the SIP body may be exported.
 * Only `structured-sanitized` (complete SDP) may keep structured content;
 * every other non-empty body is fully redacted and marked accordingly.
 */
export function decideSipBodyPolicy(
  message: SipMessage,
  buffer: Uint8Array,
): SipBodyDecision {
  const body = message.body;
  if (!body || body.span.length === 0) {
    return { kind: 'empty', reason: 'empty-body', bodySpan: null };
  }

  const encoding = sipMessageContentEncoding(message);
  if (encoding && encoding !== 'identity') {
    return {
      kind: 'unsupported',
      reason: `content-encoding:${encoding}`,
      bodySpan: body.span,
    };
  }

  const contentType = sipMessageContentType(message);
  if (isSdpContentType(contentType)) {
    const safety = evaluateAttachedSdpSafety(message, buffer);
    if (safety.kind === 'safe') {
      return {
        kind: 'structured-sanitized',
        reason: contentType ?? 'application/sdp',
        bodySpan: body.span,
      };
    }
    if (safety.kind === 'unsafe') {
      return {
        kind: 'malformed',
        reason: safety.reason,
        bodySpan: body.span,
      };
    }
    return {
      kind: 'malformed',
      reason: 'sdp-attach-failed',
      bodySpan: body.span,
    };
  }

  if (isMultipartContentType(contentType)) {
    return {
      kind: 'structured-multipart',
      reason: contentType ?? 'multipart/*',
      bodySpan: body.span,
    };
  }

  if (looksLikeRadioProtocolBody(contentType)) {
    const parsed = parseRadioProtocolBody(buffer, body.span);
    if (parsed.ok) {
      return {
        kind: 'structured-radio-protocol',
        reason: contentType ?? 'application/vnd.example.radioprotocol',
        bodySpan: body.span,
      };
    }
    return {
      kind: 'malformed',
      reason: `radio-protocol-parse-failed:${parsed.reason}`,
      bodySpan: body.span,
    };
  }

  // T37 — mission-critical / extended VoIP bodies
  if (looksLikeMcpttBody(contentType)) {
    return {
      kind: 'structured-mcptt',
      reason: contentType ?? 'application/vnd.3gpp.mcptt-info+xml',
      bodySpan: body.span,
    }
  }
  if (looksLikeDtmfRelayBody(contentType)) {
    return {
      kind: 'structured-dtmf-relay',
      reason: 'application/dtmf-relay',
      bodySpan: body.span,
    }
  }
  if (looksLikeDialogInfoBody(contentType)) {
    return {
      kind: 'structured-dialog-info',
      reason: contentType ?? 'application/dialog-info+xml',
      bodySpan: body.span,
    }
  }
  if (looksLikeSipfragBody(contentType)) {
    return {
      kind: 'structured-sipfrag',
      reason: 'message/sipfrag',
      bodySpan: body.span,
    }
  }
  if (looksLikeIsupBody(contentType)) {
    return {
      kind: 'structured-isup',
      reason: contentType ?? 'application/isup',
      bodySpan: body.span,
    }
  }

  // T49 — uaCSTA (application/csta+xml); text/xml only when body looks like CSTA
  if (looksLikeCstaContentType(contentType)) {
    const base = contentType?.trim().split(';')[0]?.trim().toLowerCase() ?? ''
    if (base === 'application/csta+xml' || base === 'application/x-csta+xml' || base.includes('csta')) {
      return {
        kind: 'structured-csta',
        reason: contentType ?? 'application/csta+xml',
        bodySpan: body.span,
      }
    }
  }

  // T53 — PIDF-LO / LoST location bodies
  if (looksLikePidfContentType(contentType)) {
    return {
      kind: 'structured-pidf',
      reason: contentType ?? 'application/pidf+xml',
      bodySpan: body.span,
    }
  }
  if (looksLikeLostContentType(contentType)) {
    return {
      kind: 'structured-lost',
      reason: contentType ?? 'application/lost+xml',
      bodySpan: body.span,
    }
  }
  // text/xml / application/xml when body looks like PIDF or LoST
  {
    const base = contentType?.trim().split(';')[0]?.trim().toLowerCase() ?? ''
    if (base === 'text/xml' || base === 'application/xml') {
      const bodyText = new TextDecoder('latin1').decode(
        buffer.subarray(body.span.offset, body.span.offset + body.span.length),
      )
      if (looksLikeLostXmlText(bodyText)) {
        return { kind: 'structured-lost', reason: 'application/lost+xml', bodySpan: body.span }
      }
      if (looksLikePidfXmlText(bodyText)) {
        return { kind: 'structured-pidf', reason: 'application/pidf+xml', bodySpan: body.span }
      }
    }
  }

  return {
    kind: 'unsupported',
    reason: contentType
      ? `unsupported-content-type:${contentType}`
      : 'missing-content-type',
    bodySpan: body.span,
  };
}

/** Coverage status for a body decision after same-length redaction. */
export function bodyCoverageStatus(
  decision: SipBodyDecision,
): 'covered' | 'redacted' | 'malformed' | null {
  switch (decision.kind) {
    case 'empty':
      return null;
    case 'structured-sanitized':
    case 'structured-radio-protocol':
    case 'structured-mcptt':
    case 'structured-dtmf-relay':
    case 'structured-dialog-info':
    case 'structured-sipfrag':
    case 'structured-isup':
    case 'structured-csta':
    case 'structured-pidf':
    case 'structured-lost':
    case 'structured-multipart':
      return 'covered';
    case 'unsupported':
    case 'fully-redacted':
      return 'redacted';
    case 'malformed':
      return 'redacted';
  }
}
