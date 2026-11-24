/**
 * R09 — wire meta for PatchCollector.addDeferred() so getSymbolicMapOps() mirrors journal map ops.
 */

import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { isPcapIdentityCategory, type IdentityCategory } from '../../mapping/identityCategories'
import { defaultWireConstraint } from '../../mapping/pcapCanonical'
import type { WireEncoderKind } from '../kernel/operations'
import type { DeferredPatchMeta } from './types'

const WIRE_ENCODER: Partial<Record<IdentityCategory, WireEncoderKind>> = {
  ipv4: 'ipv4-octets',
  ipv6: 'ipv6-octets',
  mac: 'mac-octets',
  port: 'u16-be',
  vlan: 'u16-be',
  teid: 'u32-be',
  ssrc: 'u32-be',
}

function wireMapFields(
  category: IdentityCategory,
  canonical: string,
): Pick<DeferredPatchMeta, 'canonical' | 'constraint' | 'encoder'> | null {
  // Text-only categories (email, person, …) have no binary wire shape.
  if (!isPcapIdentityCategory(category)) return null
  const constraint = defaultWireConstraint(category, canonical)
  const encoder = WIRE_ENCODER[category]
  if (!constraint || !encoder) return null
  return { canonical, constraint, encoder }
}

/** Full journal wire meta for binary map(category, canonical) deferred patches. */
export function deferredBinaryMapMeta(
  protocol: string,
  packetIndex: number,
  category: IdentityCategory,
  spelling: string,
  options?: {
    readonly fallbackKind?: DeferredPatchMeta['fallbackKind']
    readonly canonical?: string
  },
): Partial<DeferredPatchMeta> {
  const canonical = options?.canonical ?? canonicalizeIdentity(category, spelling) ?? spelling
  const wire = wireMapFields(category, canonical)
  const base: Partial<DeferredPatchMeta> = {
    fallbackKind: options?.fallbackKind ?? 'binary-mask',
    protocol,
    category,
    packetIndex,
    originalSpelling: spelling,
  }
  if (!wire) return base
  return { ...base, ...wire }
}

export function deferredPortMapMeta(
  protocol: string,
  packetIndex: number,
  transport: 'tcp' | 'udp' | 'sctp',
  port: number,
  fallbackKind: DeferredPatchMeta['fallbackKind'] = 'binary-mask',
): Partial<DeferredPatchMeta> {
  const spelling = `${transport}/${port}`
  return deferredBinaryMapMeta(protocol, packetIndex, 'port', spelling, {
    fallbackKind,
    canonical: spelling,
  })
}

/** Journal meta for SDP/MGCP o= session-version modular shift (T01 / T-01.B). */
export function deferredSessionVersionMeta(
  packetIndex: number,
  versionDigits: string,
  sessionIdCanonical: string,
): Partial<DeferredPatchMeta> {
  return {
    fallbackKind: 'digits',
    protocol: 'sdp',
    category: 'sdp-session-id',
    packetIndex,
    sessionVersionDigits: versionDigits,
    sessionIdCanonicalForVersion: sessionIdCanonical,
    reasonCode: 'sdp-session-version-shift',
  }
}

/** Journal wire meta for length-stable text aliasFor() deferred patches (fixed-ascii encoder). */
export function deferredTextMapMeta(
  protocol: string,
  packetIndex: number,
  category: IdentityCategory,
  originalSpelling: string,
  byteLength: number,
  options?: {
    readonly fallbackKind?: DeferredPatchMeta['fallbackKind']
    readonly canonical?: string
  },
): Partial<DeferredPatchMeta> {
  const canonical =
    options?.canonical ?? canonicalizeIdentity(category, originalSpelling) ?? originalSpelling
  return {
    fallbackKind: options?.fallbackKind ?? 'text-x',
    protocol,
    category,
    packetIndex,
    originalSpelling,
    canonical,
    constraint: { kind: 'text-ascii', byteLength },
    encoder: 'fixed-ascii',
  }
}
