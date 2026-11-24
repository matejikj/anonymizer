/**
 * Worker-based PCAP load port (Stage 8 internal — tests / harness only after Stage 9 cutover).
 */

import { CaptureFormat } from '../domain/types'
import type { PcapPreflightOk } from '../capture/preflight'
import { profileToSanitizationPolicy } from '../profile/presets'
import { getActivePcapProfile } from '../profile/activePcapProfile'
import { orchestrateViaWorkers } from './processingOrchestrator'

export interface WorkerLoadResult {
  generationId: string
  totalPackets: number
  entityCount: number
  intentCount: number
}

export async function loadPcapViaProcessingWorker(
  file: File,
  pre: PcapPreflightOk,
  generationId: string,
): Promise<WorkerLoadResult> {
  const profile = getActivePcapProfile()
  const policy = profileToSanitizationPolicy(profile)
  const result = await orchestrateViaWorkers({
    blob: file,
    fileName: file.name,
    format: pre.format,
    policy,
    profile,
    generationId,
    sourceId: file.name,
  })

  void result
  return {
    generationId,
    totalPackets: result.discoveryWire.totalPackets,
    entityCount: result.discoveryWire.entityCount,
    intentCount: result.discoveryWire.intentCount,
  }
}

export { CaptureFormat }
