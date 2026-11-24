/**
 * SIP/SDP sanitizer — thin orchestration over structured parser, extractor, and plan builder (step 7).
 * All patches are length-preserving; overlapping spans are deterministically dropped.
 */

import { PatchCollector } from './PatchCollector';
import type { MappingLike } from '../anonymization/mapping';
import { classifySipPayload } from '../protocols/application/sip/classify';
import { sanitizeStructuredSipMessage } from '../protocols/application/sip/sanitizeApply';
import type { SipMessage } from '../protocols/application/sip/types';

/**
 * Sanitize a parsed SIP message (and attached SDP body when present).
 */
export function sanitizeSipMessage(
  buffer: Uint8Array,
  message: SipMessage,
  transport: 'tcp' | 'udp',
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex?: number,
): readonly string[] {
  return sanitizeStructuredSipMessage(buffer, message, transport, collector, mapping, packetIndex);
}

/**
 * Classify and sanitize a SIP/SDP region within a capture buffer.
 * Returns true only when the payload is a complete SIP message that was sanitized.
 * No regex fallback — incomplete/malformed payloads return false.
 */
export function sanitizeSip(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  transport: 'tcp' | 'udp' = 'udp',
): boolean {
  const classification = classifySipPayload(buffer, offset, length, { portHint: true });
  if (classification.kind !== 'complete') return false;
  sanitizeSipMessage(buffer, classification.message, transport, collector, mapping);
  return true;
}
