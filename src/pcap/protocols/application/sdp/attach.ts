/**
 * Attach SDP parsing to a SIP message body when Content-Type matches.
 */

import type { SipMessage } from '../sip/types';
import { parseSdp, type ParseSdpOptions } from './parser';
import type { SdpParseResult, SdpSessionBundle } from './types';
import { buildSdpMediaEndpoints } from './mediaModel';

const SDP_CONTENT_TYPES = new Set([
  'application/sdp',
  'application/sdp;charset=utf-8',
]);

function normalizeContentType(value: string): string {
  return value.trim().split(';')[0]?.trim().toLowerCase() ?? '';
}

export function sipMessageContentType(message: SipMessage): string | null {
  for (const header of message.headers) {
    if (header.canonicalNameText === 'content-type') {
      return normalizeContentType(header.valueText);
    }
  }
  return null;
}

export function isSdpContentType(contentType: string | null): boolean {
  if (!contentType) return false;
  if (SDP_CONTENT_TYPES.has(contentType)) return true;
  return contentType.startsWith('application/sdp');
}

export type SipSdpAttachResult =
  | { readonly kind: 'no-sdp'; readonly reason: string }
  | { readonly kind: 'parsed'; readonly sdp: SdpParseResult; readonly contentType: string }
  | { readonly kind: 'empty-body'; readonly reason: string };

export function evaluateAttachedSdpSafety(
  message: SipMessage,
  buffer: Uint8Array,
  options: ParseSdpOptions = {},
): AttachedSdpSafety {
  const attached = parseSdpFromSipMessage(message, buffer, options);
  if (attached.kind === 'no-sdp') return { kind: 'no-sdp' };
  if (attached.kind === 'empty-body') return { kind: 'unsafe', reason: attached.reason };
  if (attached.sdp.kind !== 'complete') return { kind: 'unsafe', reason: attached.sdp.reason };
  return { kind: 'safe' };
}

export type AttachedSdpSafety =
  | { readonly kind: 'no-sdp' }
  | { readonly kind: 'safe' }
  | { readonly kind: 'unsafe'; readonly reason: string };

export function parseSdpFromSipMessage(
  message: SipMessage,
  buffer: Uint8Array,
  options: ParseSdpOptions = {},
): SipSdpAttachResult {
  const contentType = sipMessageContentType(message);
  if (!isSdpContentType(contentType)) {
    return { kind: 'no-sdp', reason: contentType ? 'content-type-mismatch' : 'missing-content-type' };
  }

  if (!message.body || message.body.span.length === 0) {
    return { kind: 'empty-body', reason: 'empty-sdp-body' };
  }

  const body = message.body.span;
  const sdp = parseSdp(buffer, {
    offset: body.offset,
    length: body.length,
    limits: options.limits,
  });

  return { kind: 'parsed', sdp, contentType: contentType! };
}

export function buildSdpSessionBundle(
  message: SipMessage,
  buffer: Uint8Array,
  options: ParseSdpOptions = {},
): SipSdpAttachResult & { readonly bundle?: SdpSessionBundle } {
  const attached = parseSdpFromSipMessage(message, buffer, options);
  if (attached.kind !== 'parsed' || attached.sdp.kind !== 'complete') {
    return attached;
  }

  const callId = findCallId(message);
  const endpoints = buildSdpMediaEndpoints(attached.sdp.session, buffer, { callId });

  return {
    ...attached,
    bundle: {
      session: attached.sdp.session,
      endpoints,
      callId,
    },
  };
}

function findCallId(message: SipMessage): string | null {
  for (const header of message.headers) {
    if (header.canonicalNameText === 'call-id') {
      return header.valueText.trim();
    }
  }
  return null;
}
