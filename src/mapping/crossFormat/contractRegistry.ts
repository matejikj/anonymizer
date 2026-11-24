/**
 * Cross-format category contract registry — compile-time gate for new categories (Stage 25 / T45).
 */

import {
  canonicalizeCrossFormatEmail,
  canonicalizeCrossFormatHostname,
  canonicalizeCrossFormatIpv4,
  canonicalizeCrossFormatIpv6,
  canonicalizeCrossFormatMac,
  canonicalizeCrossFormatPhone,
  canonicalizeCrossFormatPort,
  canonicalizeCrossFormatUser,
} from './canonicalizers'
import { CROSS_FORMAT_REPRESENTATION_STRATEGIES } from './representation'
import type { CrossFormatCategory, CrossFormatCategoryContract } from './types'
import { CROSS_FORMAT_CANONICALIZATION_VERSION } from './types'

export const CROSS_FORMAT_CATEGORY_CONTRACTS: readonly CrossFormatCategoryContract[] = [
  {
    category: 'ipv4',
    version: CROSS_FORMAT_CANONICALIZATION_VERSION,
    canonicalizer: canonicalizeCrossFormatIpv4,
    representation: CROSS_FORMAT_REPRESENTATION_STRATEGIES.ipv4,
    propertyTestId: 'cross-format-ipv4-golden',
  },
  {
    category: 'ipv6',
    version: CROSS_FORMAT_CANONICALIZATION_VERSION,
    canonicalizer: canonicalizeCrossFormatIpv6,
    representation: CROSS_FORMAT_REPRESENTATION_STRATEGIES.ipv6,
    propertyTestId: 'cross-format-ipv6-golden',
  },
  {
    category: 'mac',
    version: CROSS_FORMAT_CANONICALIZATION_VERSION,
    canonicalizer: canonicalizeCrossFormatMac,
    representation: CROSS_FORMAT_REPRESENTATION_STRATEGIES.mac,
    propertyTestId: 'cross-format-mac-golden',
  },
  {
    category: 'hostname',
    version: CROSS_FORMAT_CANONICALIZATION_VERSION,
    canonicalizer: canonicalizeCrossFormatHostname,
    representation: CROSS_FORMAT_REPRESENTATION_STRATEGIES.hostname,
    propertyTestId: 'cross-format-hostname-golden',
  },
  {
    category: 'port',
    version: CROSS_FORMAT_CANONICALIZATION_VERSION,
    canonicalizer: canonicalizeCrossFormatPort,
    representation: CROSS_FORMAT_REPRESENTATION_STRATEGIES.port,
    propertyTestId: 'cross-format-port-golden',
  },
  {
    category: 'phone',
    version: CROSS_FORMAT_CANONICALIZATION_VERSION,
    canonicalizer: canonicalizeCrossFormatPhone,
    representation: CROSS_FORMAT_REPRESENTATION_STRATEGIES.phone,
    propertyTestId: 'cross-format-phone-golden',
  },
  {
    category: 'email',
    version: CROSS_FORMAT_CANONICALIZATION_VERSION,
    canonicalizer: canonicalizeCrossFormatEmail,
    representation: CROSS_FORMAT_REPRESENTATION_STRATEGIES.email,
    propertyTestId: 'cross-format-email-golden',
  },
  {
    category: 'user',
    version: CROSS_FORMAT_CANONICALIZATION_VERSION,
    canonicalizer: canonicalizeCrossFormatUser,
    representation: CROSS_FORMAT_REPRESENTATION_STRATEGIES.user,
    propertyTestId: 'cross-format-user-golden',
  },
] as const

const REQUIRED: readonly CrossFormatCategory[] = [
  'ipv4', 'ipv6', 'mac', 'hostname', 'port', 'phone', 'email', 'user',
]

export function assertCrossFormatContractComplete(): void {
  for (const cat of REQUIRED) {
    const contract = CROSS_FORMAT_CATEGORY_CONTRACTS.find((c) => c.category === cat)
    if (!contract) {
      throw new Error(`Missing cross-format contract for ${cat}`)
    }
    if (!contract.canonicalizer || !contract.representation || !contract.propertyTestId) {
      throw new Error(`Incomplete cross-format contract for ${cat}`)
    }
  }
}

export function getCrossFormatContract(category: CrossFormatCategory): CrossFormatCategoryContract {
  const contract = CROSS_FORMAT_CATEGORY_CONTRACTS.find((c) => c.category === category)
  if (!contract) {
    throw new Error(`No cross-format contract registered for ${category}`)
  }
  return contract
}

// Fail fast at module load in dev/test bundles.
assertCrossFormatContractComplete()
