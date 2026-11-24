/**
 * PolicyCompiler — journal + mapping snapshot + policy → immutable plan patches.
 * Does not re-parse the capture; late export failures must abort, not mutate the plan.
 */

import type { MappingSnapshot } from '../../mapping/types'
import type { SanitizationPolicy } from '../sanitize/types'
import { frozenPlanFromJournalRecord, type SemanticJournal } from './journal'
import type { FrozenPacketPlan } from './frozenPlan'
import { resolveFrozenPacketPlan } from './frozenPlan'
import { SnapshotMappingAdapter } from '../plan/snapshotMappingAdapter'
import { FingerprintSession } from '../anonymization/fingerprintSession'
import type { BytePatch } from '../sanitize/types'

export interface CompiledPacketPatches {
  readonly packetIndex: number
  readonly drop: boolean
  readonly truncatedLength?: number
  readonly patches: readonly BytePatch[]
  readonly coverage: FrozenPacketPlan['coverage']
  readonly issues: readonly string[]
}

export function compileFrozenPlans(input: {
  plans: readonly FrozenPacketPlan[]
  snapshot: MappingSnapshot
  fingerprintSeed: string
  /** Reserved for T14 — policy-dependent drop/truncate already frozen at analyze time today. */
  policy?: SanitizationPolicy
}): CompiledPacketPatches[] {
  void input.policy
  const mapping = new SnapshotMappingAdapter(input.snapshot)
  const fingerprints = new FingerprintSession(input.fingerprintSeed)
  return input.plans.map((plan) => ({
    packetIndex: plan.packetIndex,
    drop: plan.drop,
    truncatedLength: plan.truncatedLength,
    patches: resolveFrozenPacketPlan(plan, {
      mapping,
      fingerprints,
      sourceId: 'pcap',
      packetIndex: plan.packetIndex,
      packetNumber: plan.packetNumber,
    }),
    coverage: plan.coverage,
    issues: plan.issues,
  }))
}

/** Project journal packet records that already carry ops (kernel-native path). */
export function frozenPlansFromJournal(journal: SemanticJournal): FrozenPacketPlan[] {
  return journal.packets.map(frozenPlanFromJournalRecord)
}
