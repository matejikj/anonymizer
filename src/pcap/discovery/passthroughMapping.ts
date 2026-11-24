/**
 * Passthrough mapping for discovery — returns canonical unchanged (no pseudonym).
 */

import type { IdentityCategory } from '../../mapping/identityCategories'
import type { MappingLike } from '../anonymization/mapping'

/** Used only during discovery; never produces pseudonyms. */
export class PassthroughMapping implements MappingLike {
  get overflow(): boolean {
    return false
  }

  map(category: IdentityCategory, canonical: string): string {
    void category
    return canonical
  }

  get(category: IdentityCategory, canonical: string): string | undefined {
    void category
    return canonical
  }

  aliasFor(
    _category: IdentityCategory,
    canonical: string,
    _constraint: import('../../mapping/types').WireRepresentationConstraint,
    originalSpelling?: string,
  ): string {
    return originalSpelling ?? canonical
  }
}
