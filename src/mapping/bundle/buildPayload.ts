/**
 * Build mapping bundle payload from a session-scoped MappingSnapshot (Stage 21 / Stage 1).
 */

import { MAPPING_BUNDLE_CANONICALIZATION_VERSION } from './formatConstants'
import type { MappingBundlePayload, MappingBundleSource } from './types'
import { requireSessionSnapshot, type MappingSnapshot } from '../types'

export function buildBundlePayloadFromSnapshot(
  snapshot: MappingSnapshot,
  sources: readonly MappingBundleSource[],
): MappingBundlePayload {
  const session = requireSessionSnapshot(snapshot)
  return {
    sessionId: `${session.sourceId}:${session.generationId}`,
    canonicalizationVersion: MAPPING_BUNDLE_CANONICALIZATION_VERSION,
    mappingRevision: session.mappingRevision,
    sources: [...sources],
    entries: session.entries.map((e) => ({
      identityId: e.identityId,
      category: e.category,
      canonical: e.canonical,
      alias: e.alias,
      disposition: e.disposition,
      occurrenceCount: e.occurrenceCount,
    })),
  }
}

export function bundleFileName(sourceLabel: string): string {
  const base = sourceLabel.replace(/[^\w.-]+/g, '_').replace(/^_|_$/g, '') || 'mapping'
  return `${base}.rnd-mapping-bundle.json`
}
