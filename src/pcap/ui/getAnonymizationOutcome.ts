/**
 * T10 — cached anonymization outcome for PCAP UI (main-thread safe).
 * Rebuilds only when plan revision changes; never scans all plan packets.
 */

import { getPcapSession } from './pcapSession'
import { getPcapCoverageViewModel } from './getPcapCoverageViewModel.ts'
import {
  buildAnonymizationOutcome,
  type AnonymizationOutcome,
} from '../coverage/anonymizationOutcome.ts'

let cachedRevision: string | null = null
let cachedOutcome: AnonymizationOutcome | null = null

export function getAnonymizationOutcome(): AnonymizationOutcome | null {
  const session = getPcapSession()
  const vm = getPcapCoverageViewModel()
  if (!session || !vm) {
    cachedRevision = null
    cachedOutcome = null
    return null
  }

  if (cachedOutcome && cachedRevision === vm.planRevision) return cachedOutcome

  const outcome = buildAnonymizationOutcome({
    protocols: vm.protocols,
    gate: vm.summary.gateBadge,
    plan: session.plan,
    incidents: session.plan.incidents,
    preset: session.plan.pcapLevel === 'high-privacy' ? 'high-privacy' : 'diagnostic',
  })
  cachedRevision = vm.planRevision
  cachedOutcome = outcome
  return outcome
}

/** Test / lifecycle helper. */
export function clearAnonymizationOutcomeCache(): void {
  cachedRevision = null
  cachedOutcome = null
}
