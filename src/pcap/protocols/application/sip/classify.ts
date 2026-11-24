/**
 * SIP payload classification — content validation with optional port hints.
 */

import type { SipParseLimits } from './limits';
import type { SipMessage } from './types';
import { parseSipMessage } from './parser';

export const SIP_PORT = 5060;
export const SIP_TLS_PORT = 5061;

export function isSipPortHint(srcPort: number, dstPort: number): boolean {
  return (
    srcPort === SIP_PORT ||
    dstPort === SIP_PORT ||
    srcPort === SIP_TLS_PORT ||
    dstPort === SIP_TLS_PORT
  );
}

export type SipPayloadClassification =
  | { readonly kind: 'complete'; readonly consumed: number; readonly message: SipMessage }
  | { readonly kind: 'incomplete'; readonly reason: string }
  | { readonly kind: 'malformed'; readonly reason: string }
  | { readonly kind: 'not-sip'; readonly reason: string };

export interface ClassifySipPayloadOptions {
  /** True when src or dst port is 5060/5061 — allows incomplete/malformed SIP signals. */
  readonly portHint?: boolean;
  readonly limits?: SipParseLimits;
}

/**
 * Classify application payload as SIP based on start-line and message structure.
 * Off-port payloads are accepted only after a complete parse (content validation).
 */
export function classifySipPayload(
  buffer: Uint8Array,
  offset: number,
  length: number,
  options: ClassifySipPayloadOptions = {},
): SipPayloadClassification {
  const portHint = options.portHint ?? false;
  const parsed = parseSipMessage(buffer, { offset, length, limits: options.limits });

  if (parsed.kind === 'complete') {
    return { kind: 'complete', consumed: parsed.consumed, message: parsed.message };
  }

  if (parsed.kind === 'not-sip') {
    return { kind: 'not-sip', reason: parsed.reason };
  }

  if (!portHint) {
    return { kind: 'not-sip', reason: 'content-validation-failed' };
  }

  if (parsed.kind === 'incomplete') {
    return { kind: 'incomplete', reason: parsed.reason };
  }

  return { kind: 'malformed', reason: parsed.reason };
}
