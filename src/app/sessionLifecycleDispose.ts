/**
 * Stage 5 — idempotent dispose of non-text session resources.
 * Text detection abort lives in sessionController to avoid an import cycle.
 */

import { clearSessionModel } from '../features/workspace/sessionModel'
import { releaseMappingSession } from '../mapping/sessionLifecycle'
import { releaseBundleCryptoSession } from '../features/mapping-bundle/bundleController'
import { clearStagingItems } from '../correlation/import/stagingModel'
import { resetCorrelationUiPhase } from '../correlation/correlationPhaseModel'
import { usePcapStore, createIdlePcapProgress } from '../pcap/ui/pcapStore'
import { cancelPcapLoad } from '../pcap/ui/pcapLoadController'
import { teardownPcapSession, teardownPcapWorkers } from '../pcap/ui/pcapSessionLifecycle'
import {
  cancelCorrelationSession,
  clearCorrelationSession,
} from '../correlation/correlationController'
import { cancelCorrelationExport } from '../correlation/export/correlationExportController'
import { closeResolveReturnAndClear } from '../features/resolve-only/resolveReturnController'

export interface DisposeSessionResourcesOptions {
  readonly keepStaging?: boolean
  readonly keepPcapUi?: boolean
  /** Keep unlock resolve-only payload (bundle import → resolve-only handoff). */
  readonly keepResolvePayload?: boolean
}

let disposing = false

/**
 * Tear down PCAP / correlation / resolve-only / shared workers / text session model.
 * Caller is responsible for aborting text detection work first when needed.
 */
export function disposeNonTextSessionResources(options: DisposeSessionResourcesOptions = {}): void {
  if (disposing) return
  disposing = true
  try {
    cancelPcapLoad()
    teardownPcapSession()
    teardownPcapWorkers()
    if (!options.keepPcapUi) {
      usePcapStore.getState().resetToEmpty()
      usePcapStore.getState().setProgress(createIdlePcapProgress())
    }

    cancelCorrelationExport()
    cancelCorrelationSession()
    clearCorrelationSession()

    if (!options.keepResolvePayload) {
      closeResolveReturnAndClear()
    }

    if (!options.keepStaging) {
      clearStagingItems()
      resetCorrelationUiPhase()
    }

    releaseMappingSession()
    if (!options.keepResolvePayload) {
      releaseBundleCryptoSession()
    }
    clearSessionModel()
  } finally {
    disposing = false
  }
}

export function resetDisposeGuardForTests(): void {
  disposing = false
}
