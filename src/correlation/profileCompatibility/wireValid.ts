/**
 * Wire-validity checks for text replacement values (Stage 26).
 */

import { normalizeIpv4Canonical, normalizeIpv6Canonical, normalizeMacCanonical } from '../../mapping/sharedNormalize'
import { isFixedTextTokenAlias } from '../../mapping/crossFormat/representation'
import type { CrossFormatCategory } from '../../mapping/crossFormat/types'

export function isWireValidIpv4(value: string): boolean {
  return normalizeIpv4Canonical(value.trim()) !== null
}

export function isWireValidIpv6(value: string): boolean {
  return normalizeIpv6Canonical(value.trim()) !== null
}

export function isWireValidMac(value: string): boolean {
  return normalizeMacCanonical(value.trim()) !== null
}

export function isWireCompatibleReplacement(category: CrossFormatCategory, value: string): boolean {
  switch (category) {
    case 'ipv4':
      return isWireValidIpv4(value) && !isFixedTextTokenAlias(value, 'ipv4')
    case 'ipv6':
      return isWireValidIpv6(value) && !isFixedTextTokenAlias(value, 'ipv6')
    case 'mac':
      return isWireValidMac(value) && !isFixedTextTokenAlias(value, 'mac')
    case 'hostname':
      return value.length > 0 && value.length <= 253 && !/\s/.test(value)
    case 'port':
      return /^(tcp|udp|sctp)\/\d{1,5}$/i.test(value.trim())
    case 'phone':
      return /\d{3,15}/.test(value.replace(/\D/g, ''))
    case 'email':
      return value.includes('@') && value.length <= 254
    case 'user':
      return value.length > 0 && value.length <= 256 && !/\s/.test(value)
  }
}
