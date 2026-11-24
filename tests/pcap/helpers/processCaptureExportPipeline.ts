/**
 * Production-shaped PCAP gate: processCapture → mapping closure → buildPlanFromSession → export.
 */

import { CaptureFormat } from '../../../src/pcap/domain/types'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import {
  createPresetProfile,
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  type PcapAnonymizationLevel,
} from '../../../src/pcap/profile/presets'
import { MappingAuthority } from '../../../src/mapping/mappingAuthority'
import {
  dedupeIdentities,
  identitiesForClosureFailures,
  validateMappingClosure,
} from '../../../src/pcap/plan/mappingClosureValidation'
import { buildCaptureFromPlan } from '../../../src/pcap/export/engine'
import type { PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import type { MappingSnapshot } from '../../../src/mapping/types'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import {
  buildPlanFromSession,
  identitiesFromDiscovery,
  processCapture,
  type ProcessingSession,
} from '../../../src/pcap/processing/processingPipeline'
import { classicHeader } from './diagnosticPipeline'

export interface ProcessCaptureExportResult {
  readonly session: ProcessingSession
  readonly plan: PcapPlanSnapshot
  readonly snapshot: MappingSnapshot
  readonly built: ReturnType<typeof buildCaptureFromPlan>
}

export async function runProcessCaptureExportPipeline(
  packets: readonly PacketEnvelope[],
  level: PcapAnonymizationLevel,
  fileName: string,
  generationId: string,
  options?: { readonly mappingSeed?: string },
): Promise<ProcessCaptureExportResult> {
  const policy = level === 'diagnostic' ? DIAGNOSTIC_POLICY : HIGH_PRIVACY_POLICY
  const profile = createPresetProfile(level, { id: generationId, name: `${level} processCapture export` })
  const header = classicHeader(packets[0]?.linkType ?? 1)
  const buffer = writeClassicPcap({ header, packets })
  const blob = new Blob([buffer])

  const session = await processCapture({
    blob,
    fileName,
    format: CaptureFormat.ClassicPcap,
    policy,
    generationId,
    sourceId: fileName,
    retainPacketsForTests: true,
  })
  if (!session.packets?.length) {
    throw new Error('processCapture export gate requires retainPacketsForTests packets')
  }

  const authority = new MappingAuthority(
    {
      ip: profile.mapping.ip,
      mac: profile.mapping.mac,
      timestamps: profile.mapping.timestamps,
      ephemeralPorts: profile.mapping.ephemeralPorts,
      contentSignalingPorts: profile.mapping.contentSignalingPorts,
      vlan: profile.mapping.vlan,
    },
    options?.mappingSeed ? { seed: options.mappingSeed } : undefined,
  )
  const identities = identitiesFromDiscovery(session.discovery)
  let resolved = authority.resolve({ generationId, sourceId: fileName, identities })
  if (!resolved.ok) throw new Error(`mapping resolve failed: ${resolved.message}`)
  let unresolvedFailures: import('../../../src/pcap/plan/mappingClosureValidation').MappingClosureFailure[] =
    []
  let closure = validateMappingClosure(session.discovery.intents, resolved.snapshot)
  if (!closure.ok) {
    const topUp = identitiesForClosureFailures(closure.failures)
    resolved = authority.resolve({
      generationId,
      sourceId: fileName,
      identities: dedupeIdentities([...identities, ...topUp]),
    })
    if (!resolved.ok) throw new Error(`mapping resolve failed: ${resolved.message}`)
    closure = validateMappingClosure(session.discovery.intents, resolved.snapshot)
    if (!closure.ok) unresolvedFailures = [...closure.failures]
  }

  const plan = buildPlanFromSession(session, resolved.snapshot, profile, undefined, {
    sourceId: fileName,
    unresolvedClosureFailures: unresolvedFailures,
  })
  const built = buildCaptureFromPlan(plan, session.packets, { applyTimestamps: false })
  return { session, plan, snapshot: resolved.snapshot, built }
}
