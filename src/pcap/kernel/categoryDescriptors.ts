/**
 * T14 — typed category / representation descriptors over existing mapping registries.
 * Not a second identity registry: wraps canonicalize + domain + wire constraint.
 */

import type { IdentityCategory } from '../../mapping/identityCategories'
import { canonicalizeIdentity, defaultIdentityWireConstraint } from '../../mapping/canonicalize'
import type { WireRepresentationConstraint } from '../../mapping/types'
import type { EntityCategory } from '../anonymization/entityRegistry'
import {
  mappingDomainFor,
  type MappingDomainSpec,
} from '../anonymization/mappingDomainRegistry'
import { isPcapIdentityCategory } from '../../mapping/identityCategories'

export interface CategoryDescriptor {
  readonly category: IdentityCategory
  readonly domain: MappingDomainSpec | null
  canonicalize(raw: string): string | null
  defaultConstraint(canonical: string, originalSpelling?: string): WireRepresentationConstraint | null
}

function descriptorFor(category: IdentityCategory): CategoryDescriptor {
  return {
    category,
    domain: isPcapIdentityCategory(category)
      ? mappingDomainFor(category as EntityCategory)
      : null,
    canonicalize: (raw) => canonicalizeIdentity(category, raw),
    defaultConstraint: (canonical, spelling) =>
      defaultIdentityWireConstraint(category, canonical, spelling),
  }
}

const CACHE = new Map<IdentityCategory, CategoryDescriptor>()

/** Typed view of an identity category for handlers (no React / raw buffer retention). */
export function categoryDescriptor(category: IdentityCategory): CategoryDescriptor {
  let d = CACHE.get(category)
  if (!d) {
    d = descriptorFor(category)
    CACHE.set(category, d)
  }
  return d
}

/** T14 — opaque session/device identifiers without a richer typed category yet. */
export const OPAQUE_ID_CATEGORY: IdentityCategory = 'opaque-id'
