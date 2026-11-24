/**
 * Text single-source mapping port (Stage 18).
 */

import type { CustomRule, ResolvedMatch } from '../domain/types'
import { collectTextIdentities } from './textIdentity'
import { buildAliasLookup, mappingKey, type CanonicalIdentity, type MappingSnapshot } from './types'
import { getSharedMappingClient, setSharedMappingClientForTests } from './sharedMappingClient'
import { MappingWorkerClient } from './mappingWorkerClient'

export { setSharedMappingClientForTests as setTextMappingClientForTests }

export function getTextMappingClient(): MappingWorkerClient {
  return getSharedMappingClient()
}

export async function resolveTextIdentities(
  generationId: string,
  sourceId: string,
  matches: readonly ResolvedMatch[],
): Promise<MappingSnapshot> {
  const identities = collectTextIdentities([...matches], sourceId)
  return getTextMappingClient().resolve(generationId, sourceId, identities)
}

export async function resolveTextIdentitiesBatch(
  generationId: string,
  sourceId: string,
  identities: readonly CanonicalIdentity[],
  customRules: readonly CustomRule[] = [],
): Promise<MappingSnapshot> {
  return getTextMappingClient().resolve(generationId, sourceId, identities, undefined, customRules)
}

export function aliasFromSnapshot(
  snapshot: MappingSnapshot,
  category: CanonicalIdentity['category'],
  canonical: string,
): string | undefined {
  return buildAliasLookup(snapshot).get(mappingKey(category, canonical))
}
