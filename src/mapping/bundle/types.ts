/**
 * Mapping bundle logical payload (Stage 20).
 * Plain JSON payload — no raw log, packet payload, mapping seed, or source file bytes.
 */

import type { IdentityCategory } from '../identityCategories'
import type { AliasDisposition } from '../types'

export type MappingBundleSourceKind = 'text' | 'pcap'

export interface MappingBundleSource {
  readonly id: string
  readonly kind: MappingBundleSourceKind
  readonly name: string
}

export interface MappingBundleEntry {
  readonly identityId: number
  readonly category: IdentityCategory
  readonly canonical: string
  readonly alias: string
  readonly disposition: AliasDisposition
  readonly occurrenceCount: number
}

export interface MappingBundlePayload {
  readonly sessionId: string
  readonly canonicalizationVersion: number
  readonly mappingRevision: number
  readonly sources: readonly MappingBundleSource[]
  readonly entries: readonly MappingBundleEntry[]
}

