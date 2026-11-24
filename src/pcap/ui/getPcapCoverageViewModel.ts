/**
 * Session → Stage 6 coverage view model (shared by all PCAP UI surfaces).
 */

import { getPcapSession } from './pcapSession'
import { sanitizerCoverageForExport } from '../processing/packedCaptureWire'
import {
  buildPcapCoverageViewModel,
  buildPlanRevision,
  type PcapCoverageViewModel,
} from '../coverage/pcapCoverageViewModel'

// PF-14: getPcapCoverageViewModel is called from 8+ components that re-render on every
// selection/scroll change, but the view model itself only actually changes when the plan
// revision (generationId:mappingRevision:profileHash:packetCount) changes. Cache the last
// built model by that revision instead of rebuilding it on every call.
let cachedPlanRevision: string | null = null
let cachedViewModel: PcapCoverageViewModel | null = null

export function getPcapCoverageViewModel(): PcapCoverageViewModel | null {
  const session = getPcapSession()
  if (!session) {
    cachedPlanRevision = null
    cachedViewModel = null
    return null
  }

  const revision = buildPlanRevision({
    generationId: session.generationId,
    mappingRevision: session.mappingRevision,
    profileHash: session.profileHash,
    planPacketCount: session.plan.packets.length,
  })
  if (cachedViewModel && cachedPlanRevision === revision) return cachedViewModel

  const model = buildPcapCoverageViewModel({
    sanitizerCoverage: sanitizerCoverageForExport(session.packetDiscovery, session.coverageRollup),
    unifiedCoverage: session.unifiedCoverage,
    policy: session.policy,
    plan: session.plan,
    statuses: session.statuses,
    generationId: session.generationId,
    mappingRevision: session.mappingRevision,
    profileHash: session.profileHash,
  })
  cachedPlanRevision = revision
  cachedViewModel = model
  return model
}
