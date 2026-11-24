/**
 * Reverse lookup port (Stage 19).
 */

import type { IdentityCategory } from './identityCategories'
import { getSharedMappingClient } from './sharedMappingClient'
import type { OccurrenceRef, ReleaseOccurrenceResult } from './types'
import type { ReverseLookupCandidate } from './reverseIndex'

export async function lookupOriginal(
  category: IdentityCategory,
  canonical: string,
): Promise<readonly ReverseLookupCandidate[]> {
  return getSharedMappingClient().lookupByOriginal(category, canonical)
}

export async function lookupAlias(alias: string): Promise<readonly ReverseLookupCandidate[]> {
  return getSharedMappingClient().lookupByAlias(alias)
}

export async function releaseOccurrence(
  category: IdentityCategory,
  canonical: string,
  occurrence: OccurrenceRef,
): Promise<ReleaseOccurrenceResult> {
  return getSharedMappingClient().releaseOccurrence(category, canonical, occurrence)
}
