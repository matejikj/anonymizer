/**
 * Wire canonical keys and alias resolution for SIP/SDP sanitization (step 7).
 * CF-02: text spans use constraint-aware aliasFor(), never silent truncation.
 */

import { canonicalizeIdentity } from '../../../../mapping/canonicalize';
import type { IdentityCategory } from '../../../../mapping/identityCategories';
import type { WireRepresentationConstraint } from '../../../../mapping/types';
import type { MappingLike } from '../../../anonymization/mapping';

export type PortContext = 'signaling' | 'media';

export function wirePortCanonical(
  portText: string,
  transport: 'tcp' | 'udp',
  context: PortContext,
): string {
  const port = Number.parseInt(portText, 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535) return portText;
  const proto = context === 'media' ? 'udp' : transport;
  return `${proto}/${port}`;
}

function textAsciiConstraint(byteLength: number): WireRepresentationConstraint {
  return { kind: 'text-ascii', byteLength };
}

export function resolveIdentityAlias(
  mapping: MappingLike,
  category: string,
  canonicalText: string,
  transport: 'tcp' | 'udp',
  portContext: PortContext,
  originalSpelling: string,
): string {
  const byteLength = originalSpelling.length;

  if (category === 'port') {
    const wire = wirePortCanonical(canonicalText, transport, portContext);
    return mapping.aliasFor('port', wire, textAsciiConstraint(byteLength), originalSpelling);
  }

  if (category === 'sip-phone') {
    const canonical = canonicalizeIdentity('sip-phone', canonicalText) ?? canonicalText;
    return mapping.aliasFor('sip-phone', canonical, textAsciiConstraint(byteLength), originalSpelling);
  }

  const identityCategory = category as IdentityCategory;
  const canonical = canonicalizeIdentity(identityCategory, canonicalText) ?? canonicalText;

  if (identityCategory === 'ipv4' || identityCategory === 'ipv6' || identityCategory === 'hostname') {
    return mapping.aliasFor(
      identityCategory,
      canonical,
      textAsciiConstraint(byteLength),
      originalSpelling,
    );
  }

  if (
    identityCategory === 'sip-call-id'
    || identityCategory === 'sip-token'
    || identityCategory === 'sip-user'
    || identityCategory === 'sdp-session-id'
  ) {
    return mapping.aliasFor(
      identityCategory,
      canonical,
      textAsciiConstraint(byteLength),
      originalSpelling,
    );
  }

  const wireConstraint = canonicalizeIdentity(identityCategory, canonicalText)
    ? { kind: 'text-ascii' as const, byteLength }
    : textAsciiConstraint(byteLength);
  return mapping.aliasFor(identityCategory, canonical, wireConstraint, originalSpelling);
}
