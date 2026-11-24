/**
 * Record SIP/SDP discovery intents for MappingAuthority (step 6).
 * Body intents come from {@link planSipBodyOperations} (shared with plan — T02).
 * Spans are absolute offsets in the capture buffer passed to the SIP parser.
 */

import type { IntentCollector } from '../../../discovery/intentCollector';
import type { IdentityCategory } from '../../../../mapping/identityCategories';
import { wirePortCanonical, type PortContext } from './mappingWire';
import { extractSipEntities } from './extract';
import type { SipMappingCategory, SipSensitiveEntity } from './entities';
import type { ByteSpan, SipMessage } from './types';
import { decodeLatin1Span } from './bytes';
import { planSipBodyOperations } from './bodyOperations';
import { buildSdpSessionBundle } from '../sdp/attach';

function spanText(buffer: Uint8Array, span: ByteSpan): string {
  return decodeLatin1Span(buffer, span);
}

function toIdentityCategory(category: SipMappingCategory | string): IdentityCategory {
  return category as IdentityCategory;
}

function recordMappedEntity(
  intents: IntentCollector,
  buffer: Uint8Array,
  packetIndex: number,
  span: ByteSpan,
  category: IdentityCategory,
  canonicalText: string,
  transport: 'tcp' | 'udp',
  portContext: PortContext,
): void {
  const originalSpelling = spanText(buffer, span);
  let rawCanonical = canonicalText;
  if (category === 'port') {
    rawCanonical = wirePortCanonical(canonicalText, transport, portContext);
  }
  const constraint = textSpanConstraint(category, span.length);
  intents.recordEntityReplacement(
    packetIndex,
    span.offset,
    category,
    rawCanonical,
    span.length,
    constraint,
    originalSpelling,
  );
}

function textSpanConstraint(category: IdentityCategory, byteLength: number) {
  if (
    category === 'ipv4'
    || category === 'ipv6'
    || category === 'hostname'
    || category === 'port'
    || category === 'sip-phone'
    || category === 'sip-call-id'
    || category === 'sip-token'
    || category === 'sip-user'
    || category === 'sdp-session-id'
  ) {
    return { kind: 'text-ascii' as const, byteLength };
  }
  return undefined;
}

function recordSipEntity(
  intents: IntentCollector,
  buffer: Uint8Array,
  packetIndex: number,
  entity: SipSensitiveEntity,
  transport: 'tcp' | 'udp',
): void {
  if (entity.action !== 'map' || entity.mappingCategory === null) return;
  const mappingCategory = entity.mappingCategory;
  if (mappingCategory === 'sip-phone') {
    intents.recordEntityReplacement(
      packetIndex,
      entity.span.offset,
      'sip-phone',
      entity.canonicalText,
      entity.span.length,
      { kind: 'text-ascii', byteLength: entity.span.length },
      spanText(buffer, entity.span),
    );
    return;
  }
  recordMappedEntity(
    intents,
    buffer,
    packetIndex,
    entity.span,
    toIdentityCategory(mappingCategory),
    entity.canonicalText,
    transport,
    'signaling',
  );
}

export function recordSipSdpDiscoveryIntents(
  intents: IntentCollector,
  buffer: Uint8Array,
  message: SipMessage,
  transport: 'tcp' | 'udp',
  packetIndex: number,
): void {
  const { entities: sipEntities } = extractSipEntities(message, buffer);
  for (const entity of sipEntities) {
    if (entity.action === 'redact') {
      intents.recordFixedRedaction(packetIndex, entity.span.offset, entity.span.length);
      continue;
    }
    recordSipEntity(intents, buffer, packetIndex, entity, transport);
  }

  const bodyPlan = planSipBodyOperations(message, buffer);
  for (const op of bodyPlan.operations) {
    if (op.action === 'redact') {
      intents.recordFixedRedaction(packetIndex, op.span.offset, op.span.length);
      continue;
    }
    // session-version: deferred shift, not a MappingAuthority identity
    if (op.sessionIdForVersion !== undefined && op.mappingCategory === null) continue;
    if (op.mappingCategory === null) continue;
    recordMappedEntity(
      intents,
      buffer,
      packetIndex,
      op.span,
      toIdentityCategory(op.mappingCategory),
      op.canonicalText,
      transport,
      op.portContext,
    );
  }

  // T06 revision — SDP-negotiated RTP/RTCP mates (incl. non-+1 a=rtcp / mux).
  const attached = buildSdpSessionBundle(message, buffer)
  if (attached.kind === 'parsed' && attached.sdp.kind === 'complete' && attached.bundle) {
    for (const endpoint of attached.bundle.endpoints) {
      const rtpCanon = `udp/${endpoint.port}`
      if (endpoint.rtcpPort !== null && endpoint.rtcpPort !== undefined) {
        intents.recordMediaPortPair(rtpCanon, `udp/${endpoint.rtcpPort}`)
      } else {
        intents.recordPortFlowHint(rtpCanon, 'rtp')
      }
    }
  }
}
