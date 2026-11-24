/**
 * Stage 5 — inventory of long-lived resources and ownership.
 * Large payloads must never enter React/Zustand; only UI projection fields may.
 */

export type SessionKind =
  | 'none'
  | 'text'
  | 'pcap'
  | 'correlation'
  | 'resolve-only'

export type LifecycleResourceId =
  | 'detection-worker'
  | 'export-worker'
  | 'mapping-worker'
  | 'pcap-processing-worker'
  | 'pcap-export-worker'
  | 'text-session-model'
  | 'pcap-session'
  | 'pcap-preview-lru'
  | 'correlation-session'
  | 'correlation-staging'
  | 'mapping-staging-transaction'
  | 'resolve-only-payload'
  | 'abort-controllers'
  | 'pending-export-sinks'

export interface LifecycleResourceSpec {
  readonly id: LifecycleResourceId
  readonly owner: string
  readonly create: string
  readonly cancel: string
  readonly dispose: string
  readonly idempotent: true
  readonly neverInZustand: boolean
}

/** Documented ownership map (Stage 5.1). */
export const LIFECYCLE_RESOURCE_INVENTORY: readonly LifecycleResourceSpec[] = [
  {
    id: 'detection-worker',
    owner: 'sessionController / DetectionWorkerClient',
    create: 'getClient()',
    cancel: 'DetectionWorkerClient.cancel()',
    dispose: 'DetectionWorkerClient.dispose()',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'export-worker',
    owner: 'exportCoordinator / exportWorkerClient',
    create: 'createExportWorker()',
    cancel: 'job AbortController',
    dispose: 'worker.terminate on session reset',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'mapping-worker',
    owner: 'sharedMappingClient',
    create: 'getSharedMappingClient()',
    cancel: 'abortStaging / cancel(generation)',
    dispose: 'releaseMappingSession()',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'pcap-processing-worker',
    owner: 'pcap processingOrchestrator / correlation PcapSourceAdapter',
    create: 'orchestrateViaWorkers() / per-source correlation transaction',
    cancel: 'cancelActiveProcessing(generationId) / correlation AbortSignal',
    dispose: 'resetProcessingClients / terminate after correlation buildPlan',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'pcap-export-worker',
    owner: 'pcap export coordinator',
    create: 'runPcapExport()',
    cancel: 'cancelPcapExport()',
    dispose: 'onPcapSessionClosed',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'text-session-model',
    owner: 'features/workspace/sessionModel',
    create: 'buildSessionModel()',
    cancel: 'n/a (immutable replace)',
    dispose: 'clearSessionModel()',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'pcap-session',
    owner: 'pcap/ui/pcapSession',
    create: 'createSlimPcapSession()',
    cancel: 'cancelPcapLoad()',
    dispose: 'teardownPcapSession / clearPcapSession',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'pcap-preview-lru',
    owner: 'pcapPreviewController',
    create: 'preview requests',
    cancel: 'cancelPendingPreviews()',
    dispose: 'resetPreviewController()',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'correlation-session',
    owner: 'correlationSessionModel',
    create: 'createCorrelationSessionModel()',
    cancel: 'cancelCorrelationSession()',
    dispose: 'clearCorrelationSession()',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'correlation-staging',
    owner: 'correlation/import/stagingModel',
    create: 'replaceStagingItems / mergeFilesIntoStaging',
    cancel: 'n/a',
    dispose: 'clearStagingItems()',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'mapping-staging-transaction',
    owner: 'correlationTransaction + MappingAuthority staging',
    create: 'runSourceTransaction / resolveStaging',
    cancel: 'abortActiveSourceTransaction()',
    dispose: 'abort + clearCorrelationSession',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'resolve-only-payload',
    owner: 'resolveOnlyModel',
    create: 'setResolveOnlyPayload()',
    cancel: 'cancelBundleJob()',
    dispose: 'clearResolveOnlyModel + releaseBundleCryptoSession',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'abort-controllers',
    owner: 'per-controller module scope',
    create: 'new AbortController() / CancellationToken',
    cancel: 'abort()',
    dispose: 'null out refs',
    idempotent: true,
    neverInZustand: true,
  },
  {
    id: 'pending-export-sinks',
    owner: 'export sinks / directory handles',
    create: 'createDirectoryFileSink / BlobExportSink',
    cancel: 'AbortSignal / cancel export',
    dispose: 'finalize or drop without download',
    idempotent: true,
    neverInZustand: true,
  },
] as const

/** Data that must never be stored in Zustand (Stage 5 acceptance). */
export const ZUSTAND_FORBIDDEN_PAYLOADS = [
  'log-text',
  'packet-bytes',
  'mapping-registry',
  'decrypted-bundle',
  'pcap-descriptors',
] as const

export type LifecycleTransition =
  | { readonly from: SessionKind; readonly to: SessionKind; readonly allowed: true }
  | { readonly from: SessionKind; readonly to: SessionKind; readonly allowed: false; readonly reason: string }

/**
 * Allowed session-kind transitions. Starting a new large session always disposes the previous
 * one first (except correlation which may hold multiple sources by design).
 */
export function isLifecycleTransitionAllowed(from: SessionKind, to: SessionKind): boolean {
  if (from === to) return true
  if (to === 'none') return true
  if (from === 'none') return true
  // Replacing any large session with another is allowed only via dispose-then-start.
  return true
}

export function requiresExclusiveDispose(from: SessionKind, to: SessionKind): boolean {
  if (from === 'none' || to === 'none') return false
  if (from === to) return false
  // Correlation may replace text/pcap; never hold two exclusive large sessions.
  return true
}
