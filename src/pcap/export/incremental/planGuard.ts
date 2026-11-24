/**
 * Export plan validation — reject stale or unknown plans (Stage 11).
 */

import type { PcapPlanSnapshot } from '../planSnapshot'
import { PCAP_ENGINE_VERSION } from '../planSnapshot'

export class ExportPlanRejectedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ExportPlanRejectedError'
  }
}

export function assertExportPlan(input: {
  plan: PcapPlanSnapshot
  expectedGenerationId?: string
  expectedProfileHash?: string
  expectedPolicyHash?: string
}): void {
  if (input.plan.engineVersion !== PCAP_ENGINE_VERSION) {
    throw new ExportPlanRejectedError(`Unsupported plan engine version: ${input.plan.engineVersion}`)
  }
  if (input.expectedGenerationId && input.plan.generationId !== input.expectedGenerationId) {
    throw new ExportPlanRejectedError('Plan generation mismatch')
  }
  const expectedHash = input.expectedPolicyHash ?? input.expectedProfileHash
  if (expectedHash && input.plan.profileHash !== expectedHash) {
    throw new ExportPlanRejectedError('Plan policy hash mismatch')
  }
}
