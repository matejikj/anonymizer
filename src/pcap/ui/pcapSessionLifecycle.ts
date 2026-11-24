/**
 * PCAP session lifecycle — worker termination, preview cancel, LRU cleanup (Stage 9).
 */

import { clearPcapSession } from './pcapSession'
import { cancelPendingPreviews, resetPreviewController } from '../preview/pcapPreviewController'
import { resetProcessingClients } from '../processing/processingOrchestrator'
import { releaseMappingSession } from '../../mapping/sessionLifecycle'
import { releaseBundleCryptoSession } from '../../features/mapping-bundle/bundleController'
import { disposeActiveRecoverySession } from '../recovery/restore/activeRecoverySession'
import { disposeProtocolGraphStateForSession } from '../sanitize/protocolGraphState.ts'
import { disposeFlowExportCachesForSession } from '../sanitize/flowExport.ts'

let activeWorkerGenerationId: string | null = null

export function getActiveWorkerGenerationId(): string | null {
  return activeWorkerGenerationId
}

export function setActiveWorkerGenerationId(id: string | null): void {
  activeWorkerGenerationId = id
}

export function teardownPcapSession(sessionGeneration?: number): void {
  if (sessionGeneration !== undefined) {
    resetPreviewController(sessionGeneration)
  }
  cancelPendingPreviews()
  clearPcapSession()
  disposeProtocolGraphStateForSession()
  disposeFlowExportCachesForSession()
  activeWorkerGenerationId = null
}

export function teardownPcapWorkers(): void {
  if (activeWorkerGenerationId) {
    // Clients cancel via orchestrator on next load; full terminate on close.
    activeWorkerGenerationId = null
  }
  resetProcessingClients()
}

export function prepareNewPcapSession(generation: number, workerGenerationId: string): void {
  cancelPendingPreviews()
  resetPreviewController(generation)
  activeWorkerGenerationId = workerGenerationId
}

export function onPcapSessionClosed(): void {
  teardownPcapSession()
  teardownPcapWorkers()
  releaseMappingSession()
  releaseBundleCryptoSession()
  void disposeActiveRecoverySession()
}
