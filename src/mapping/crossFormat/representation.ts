/**
 * Cross-format representation strategies and constraint compatibility (Stage 25).
 */

import type { WireRepresentationConstraint } from '../types'
import type { CrossFormatCategory, RepresentationCompatibility, RepresentationStrategy } from './types'

export const CROSS_FORMAT_REPRESENTATION_STRATEGIES: Readonly<Record<CrossFormatCategory, RepresentationStrategy>> = {
  ipv4: { category: 'ipv4', version: 1, usesWireEngine: true, requiresTransportContext: false },
  ipv6: { category: 'ipv6', version: 1, usesWireEngine: true, requiresTransportContext: false },
  mac: { category: 'mac', version: 1, usesWireEngine: true, requiresTransportContext: false },
  hostname: { category: 'hostname', version: 1, usesWireEngine: false, requiresTransportContext: false },
  port: { category: 'port', version: 1, usesWireEngine: true, requiresTransportContext: true },
  phone: { category: 'phone', version: 1, usesWireEngine: false, requiresTransportContext: false },
  email: { category: 'email', version: 1, usesWireEngine: false, requiresTransportContext: false },
  user: { category: 'user', version: 1, usesWireEngine: false, requiresTransportContext: false },
}

export function representationStrategyFor(category: CrossFormatCategory): RepresentationStrategy {
  return CROSS_FORMAT_REPRESENTATION_STRATEGIES[category]
}

function constraintKey(c: WireRepresentationConstraint): string {
  switch (c.kind) {
    case 'ipv4-wire':
    case 'ipv6-wire':
    case 'mac-wire':
    case 'vlan-wire':
    case 'timestamp-wire':
      return c.kind
    case 'hostname-ascii':
      return `hostname:${c.labelCount}:${c.maxLabelLength}`
    case 'port-wire':
      return `port:${c.protocol}`
    case 'radio-id-wire':
      return `radio:${c.bitWidth}`
    case 'ssrc-wire':
      return c.kind
    case 'text-ascii':
      return `text:${c.byteLength}`
  }
}

export function constraintsCompatible(
  category: CrossFormatCategory,
  a: WireRepresentationConstraint,
  b: WireRepresentationConstraint,
): RepresentationCompatibility {
  if (constraintKey(a) === constraintKey(b)) {
    return { compatible: true, sharedAlias: true }
  }

  if (category === 'hostname') {
    const text = a.kind === 'text-ascii' ? a : b.kind === 'text-ascii' ? b : null
    const wire = a.kind === 'hostname-ascii' ? a : b.kind === 'hostname-ascii' ? b : null
    if (text && wire) {
      return {
        compatible: true,
        sharedAlias: false,
        reason: 'hostname-text-vs-wire',
      }
    }
    if (a.kind === 'hostname-ascii' && b.kind === 'hostname-ascii') {
      if (a.labelCount === b.labelCount && a.maxLabelLength === b.maxLabelLength) {
        return { compatible: true, sharedAlias: true }
      }
      return {
        compatible: true,
        sharedAlias: false,
        reason: 'hostname-wire-constraint-mismatch',
      }
    }
  }

  if (category === 'ipv4' || category === 'ipv6' || category === 'mac') {
    const wireKinds = new Set(['ipv4-wire', 'ipv6-wire', 'mac-wire'])
    if (wireKinds.has(a.kind) && wireKinds.has(b.kind)) {
      return { compatible: true, sharedAlias: true }
    }
    if (a.kind === 'text-ascii' && wireKinds.has(b.kind)) {
      return { compatible: true, sharedAlias: false, reason: 'text-token-vs-wire' }
    }
    if (b.kind === 'text-ascii' && wireKinds.has(a.kind)) {
      return { compatible: true, sharedAlias: false, reason: 'text-token-vs-wire' }
    }
  }

  if (category === 'port') {
    if (a.kind === 'port-wire' && b.kind === 'port-wire' && a.protocol === b.protocol) {
      return { compatible: true, sharedAlias: true }
    }
    return { compatible: false, reason: 'port-transport-mismatch' }
  }

  // T45 — phone/email/user: same text-ascii length → shared; different lengths → linked representations.
  if (category === 'phone' || category === 'email' || category === 'user') {
    if (a.kind === 'text-ascii' && b.kind === 'text-ascii') {
      if (a.byteLength === b.byteLength) {
        return { compatible: true, sharedAlias: true }
      }
      return {
        compatible: true,
        sharedAlias: false,
        reason: `${category}-text-length-mismatch`,
      }
    }
  }

  return { compatible: false, reason: 'constraint-kind-mismatch' }
}

/** Reject generic text tokens like ip-1 — not wire-valid shared pseudonyms. */
export function isFixedTextTokenAlias(alias: string, category: CrossFormatCategory): boolean {
  if (category === 'ipv4' || category === 'ipv6' || category === 'mac') {
    return /^ip-\d+$/i.test(alias) || /^mac-\d+$/i.test(alias)
  }
  return false
}
