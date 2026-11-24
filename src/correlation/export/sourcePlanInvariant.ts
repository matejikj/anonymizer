/**
 * Source plan / discovery / session invariants for export (Stage 1).
 */

import type { CorrelationSourceRecord } from '../types'

export function assertSourcePlanInvariant(record: CorrelationSourceRecord): void {
  const plan = record.plan
  const discovery = record.discovery
  if (!plan || !discovery) {
    throw new Error(`Source ${record.sourceId} missing plan or discovery for export`)
  }
  if (plan.sourceId !== record.sourceId) {
    throw new Error(`Plan sourceId ${plan.sourceId} does not match record ${record.sourceId}`)
  }
  if (plan.generationId !== discovery.generationId) {
    throw new Error(
      `Plan generationId ${plan.generationId} does not match discovery ${discovery.generationId}`,
    )
  }
  if (discovery.sourceId !== record.sourceId) {
    throw new Error(`Discovery sourceId ${discovery.sourceId} does not match record ${record.sourceId}`)
  }
  if (!Number.isInteger(plan.mappingRevision) || plan.mappingRevision < 0) {
    throw new Error(`Plan mappingRevision invalid for source ${record.sourceId}`)
  }
  if ('profileRevision' in plan) {
    if (!Number.isInteger(plan.profileRevision) || plan.profileRevision < 0) {
      throw new Error(`Plan profileRevision invalid for source ${record.sourceId}`)
    }
  }
  if (plan.kind === 'pcap') {
    const pcapPlan = plan.plan as { profileHash?: string; policyHash?: string }
    const policyHash = pcapPlan.policyHash ?? pcapPlan.profileHash
    if (typeof policyHash !== 'string' || policyHash.length === 0) {
      throw new Error(`PCAP plan policyHash missing for source ${record.sourceId}`)
    }
  }
}
