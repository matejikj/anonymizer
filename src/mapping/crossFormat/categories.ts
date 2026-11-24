/**
 * Map format-local categories to cross-format contract categories (Stage 25 / T45).
 */

import type { Category } from '../../domain/types'
import type { IdentityCategory } from '../identityCategories'
import { isPcapIdentityCategory, isTextIdentityCategory } from '../identityCategories'
import type { WireRepresentationConstraint } from '../types'
import { canonicalizeCrossFormatCategory } from './canonicalizers'
import type { CrossFormatCategory, CrossFormatSourceKind } from './types'

/** International / tel: evidence of phone role for SIP user parts (T45). */
function looksLikePhoneRole(raw: string): boolean {
  const trimmed = raw.trim()
  if (/^(?:tel|sip):/i.test(trimmed)) return true
  const afterScheme = trimmed.replace(/^(?:tel|sip):/i, '')
  return afterScheme.startsWith('+')
}

export function crossFormatCategoryFromIdentity(
  category: IdentityCategory,
  raw: string,
  constraint?: WireRepresentationConstraint,
): CrossFormatCategory | null {
  const source: CrossFormatSourceKind = isPcapIdentityCategory(category) ? 'pcap' : 'text'

  if (category === 'ip' || category === 'ipv4') {
    const canon = canonicalizeCrossFormatCategory('ipv4', raw, source)
    return canon ? 'ipv4' : null
  }
  if (category === 'ipv6') {
    const canon = canonicalizeCrossFormatCategory('ipv6', raw, source)
    return canon ? 'ipv6' : null
  }
  if (category === 'mac') {
    const canon = canonicalizeCrossFormatCategory('mac', raw, source)
    return canon ? 'mac' : null
  }
  if (category === 'hostname') {
    const canon = canonicalizeCrossFormatCategory('hostname', raw, source)
    return canon ? 'hostname' : null
  }
  if (category === 'port') {
    if (constraint?.kind === 'port-wire' && constraint.protocol === 'unknown') return null
    const canon = canonicalizeCrossFormatCategory('port', raw, source)
    return canon ? 'port' : null
  }

  // T45 — phone / email / user cross-format participants.
  if (category === 'sip-phone') {
    const canon = canonicalizeCrossFormatCategory('phone', raw, source)
    return canon ? 'phone' : null
  }
  if (category === 'email') {
    const canon = canonicalizeCrossFormatCategory('email', raw, source)
    return canon ? 'email' : null
  }
  if (category === 'user-id') {
    const canon = canonicalizeCrossFormatCategory('user', raw, source)
    return canon ? 'user' : null
  }
  if (category === 'sip-user') {
    // Bare numeric SIP users stay user principals; + / tel: / extract user=phone → phone.
    if (looksLikePhoneRole(raw)) {
      const phone = canonicalizeCrossFormatCategory('phone', raw, source)
      return phone ? 'phone' : null
    }
    const user = canonicalizeCrossFormatCategory('user', raw, source)
    return user ? 'user' : null
  }

  // Explicit non-participants: SDP session-id / IMSI / IMEI / SNMP engine stay PCAP-local.
  if (
    category === 'sdp-session-id'
    || category === 'imsi'
    || category === 'imei'
    || category === 'snmp-engine-id'
    || category === 'teid'
    || category === 'point-code'
    || category === 'ssid'
    || category === 'ssrc'
    || category === 'radioId'
  ) {
    return null
  }

  void isTextIdentityCategory
  return null
}

export function storageCategoryForCrossFormat(cf: CrossFormatCategory): IdentityCategory {
  switch (cf) {
    case 'ipv4':
      return 'ipv4'
    case 'ipv6':
      return 'ipv6'
    case 'mac':
      return 'mac'
    case 'hostname':
      return 'hostname'
    case 'port':
      return 'port'
    case 'phone':
      return 'sip-phone'
    case 'email':
      return 'email'
    case 'user':
      return 'user-id'
  }
}

export function alternateLookupKeys(
  cf: CrossFormatCategory,
  canonical: string,
): readonly string[] {
  const keys: string[] = [crossFormatRegistryKey(cf, canonical)]
  switch (cf) {
    case 'ipv4':
      keys.push(`ip:${canonical}`)
      keys.push(`ipv4:${canonical}`)
      break
    case 'ipv6':
      keys.push(`ip:${canonical}`)
      keys.push(`ipv6:${canonical}`)
      break
    case 'mac':
      keys.push(`mac:${canonical}`)
      break
    case 'hostname':
      keys.push(`hostname:${canonical}`)
      break
    case 'port':
      keys.push(`port:${canonical}`)
      break
    case 'phone':
      keys.push(`sip-phone:${canonical}`)
      break
    case 'email':
      keys.push(`email:${canonical}`)
      break
    case 'user':
      keys.push(`user-id:${canonical}`)
      keys.push(`sip-user:${canonical}`)
      break
  }
  return keys
}

export function crossFormatRegistryKey(cf: CrossFormatCategory, canonical: string): string {
  return `cf:v1:${cf}:${canonical}`
}

export function crossFormatRegistryKeyFromIdentity(
  category: IdentityCategory,
  raw: string,
  constraint?: WireRepresentationConstraint,
): string | null {
  const cf = crossFormatCategoryFromIdentity(category, raw, constraint)
  if (!cf) return null
  const source: CrossFormatSourceKind = isPcapIdentityCategory(category) ? 'pcap' : 'text'
  const canonical = canonicalizeCrossFormatCategory(cf, raw, source)
  if (!canonical) return null
  return crossFormatRegistryKey(cf, canonical)
}

export function isFormatLocalOnlyCategory(category: IdentityCategory): boolean {
  if (isPcapIdentityCategory(category)) {
    return category === 'vlan' || category === 'timestamp' || category === 'radioId'
      || category === 'teid'
      || category === 'point-code'
      || category === 'ssid'
      || category === 'sip-call-id' || category === 'sip-token'
  }
  if (isTextIdentityCategory(category)) {
    // T45 — sip-phone / email / user-id participate in cross-format; person stays local.
    const textOnly: Category[] = ['person', 'internal-id', 'custom']
    return textOnly.includes(category as Category)
  }
  return true
}

export function usesSharedWireEngine(category: IdentityCategory, raw: string, constraint?: WireRepresentationConstraint): boolean {
  const cf = crossFormatCategoryFromIdentity(category, raw, constraint)
  if (!cf) return false
  return cf === 'ipv4' || cf === 'ipv6' || cf === 'mac' || cf === 'port'
}

/** T45 — phone/email/user allocate via TextAliasEngine (length-preserving text slots). */
export function usesCrossFormatTextEngine(
  category: IdentityCategory,
  raw: string,
  constraint?: WireRepresentationConstraint,
): boolean {
  const cf = crossFormatCategoryFromIdentity(category, raw, constraint)
  return cf === 'phone' || cf === 'email' || cf === 'user'
}
