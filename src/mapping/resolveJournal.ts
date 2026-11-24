/**
 * Bounded resolve journal — Stage 24 multi-source staging transactions.
 * Stores alias-engine deltas and pending identity registrations without copying the full registry.
 */

import type { CustomRule } from '../domain/types'
import {
  SessionMapping,
} from '../pcap/anonymization/mapping'
import { TextAliasEngine } from './textAliasEngine'
import type { CanonicalIdentity } from './types'

export interface ResolveJournalBatch {
  readonly generationId: string
  readonly sourceId: string
  readonly customRules?: readonly CustomRule[]
  readonly identities: readonly CanonicalIdentity[]
  readonly stagingPcap: SessionMapping
  readonly stagingText: TextAliasEngine
  readonly stagingAliases: ReadonlyMap<string, string>
}

export function createResolveJournalBatch(input: {
  generationId: string
  sourceId: string
  customRules?: readonly CustomRule[]
  identities: readonly CanonicalIdentity[]
  stagingPcap: SessionMapping
  stagingText: TextAliasEngine
  stagingAliases: Map<string, string>
}): ResolveJournalBatch {
  return {
    generationId: input.generationId,
    sourceId: input.sourceId,
    customRules: input.customRules,
    identities: input.identities,
    stagingPcap: input.stagingPcap,
    stagingText: input.stagingText,
    stagingAliases: input.stagingAliases,
  }
}
