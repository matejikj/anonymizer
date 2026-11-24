/**
 * PCAP single-source mapping port (Stage 7 internal foundation).
 * Not wired to production sanitization until Stage 9 cutover.
 */

import type { EntityCategory } from '../anonymization/entityRegistry'
import { DEFAULT_MAPPING_CONFIG, type MappingConfig } from '../anonymization/mapping'
import { getSharedMappingClient, resetSharedMappingClient, setSharedMappingClientForTests } from '../../mapping/sharedMappingClient'
import { canonicalizePcapIdentity, defaultWireConstraint } from '../../mapping/pcapCanonical'
import type { CanonicalIdentity, MappingSnapshot } from '../../mapping/types'
import { buildAliasLookup } from '../../mapping/types'

export interface PcapIdentityInput {
  category: EntityCategory
  canonical: string
}

/** Test hook — inject in-process worker client (Stage 7 tests only). */
export function setPcapMappingClientForTests(client: import('../../mapping/mappingWorkerClient').MappingWorkerClient | null): void {
  setSharedMappingClientForTests(client)
}

export function getPcapMappingClient() {
  return getSharedMappingClient()
}

export function resetPcapMappingClient(): void {
  resetSharedMappingClient()
}

export async function resolvePcapIdentities(
  generationId: string,
  sourceId: string,
  inputs: readonly PcapIdentityInput[],
  config: MappingConfig = DEFAULT_MAPPING_CONFIG,
): Promise<MappingSnapshot> {
  const identities: CanonicalIdentity[] = []
  for (const input of inputs) {
    const canonical = canonicalizePcapIdentity(input.category, input.canonical)
    if (canonical === null) continue
    const constraint = defaultWireConstraint(input.category, canonical)
    if (constraint === null) continue
    identities.push({ category: input.category, canonical, constraint })
  }
  return getPcapMappingClient().resolve(generationId, sourceId, identities, config)
}

export function aliasFromSnapshot(
  snapshot: MappingSnapshot,
  category: EntityCategory,
  canonical: string,
): string | undefined {
  return buildAliasLookup(snapshot).get(`${category}:${canonical}`)
}
