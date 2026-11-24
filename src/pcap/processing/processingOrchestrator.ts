/**
 * Stage 9 orchestration — processing worker + mapping worker (production cutover).
 */

import { CaptureFormat } from '../domain/types'
import type { SanitizationPolicy } from '../sanitize/types'
import type { PcapProfile } from '../profile/schema'
import { MappingWorkerClient } from '../../mapping/mappingWorkerClient'
import {
  getSharedMappingClient,
  setSharedMappingClientForTests,
} from '../../mapping/sharedMappingClient'
import type { MappingSnapshot, CanonicalIdentity } from '../../mapping/types'
import { PcapProcessingWorkerClient } from './pcapProcessingWorkerClient'
import {
  identitiesFromDiscovery,
  processCapture,
  buildPlanFromSession,
  containerMetadataFromSession,
  discoveryToWire,
} from './processingPipeline'
import type { SourceDiscovery, TransformationIntent } from '../discovery/types'
import type { PcapPlanSnapshot } from '../export/planSnapshot'
import type { WireSourceDiscoveryPayload } from './workerProtocol'
import type { WireContainerMetadata } from './containerWireAdapter'
import { canonicalizePcapIdentity, defaultWireConstraint } from '../../mapping/pcapCanonical'
import type { EntityCategory } from '../anonymization/entityRegistry'
import type { AnalysisResult } from '../protocols/analysis'
import {
  dedupeIdentities,
  resolveSnapshotWithMappingClosure,
} from '../plan/mappingClosureValidation'
import { constraintKey } from '../../mapping/constraintKey'

export interface ProcessingOrchestrationResult {
  discovery: SourceDiscovery
  discoveryWire: WireSourceDiscoveryPayload
  containerWire: ReturnType<typeof containerMetadataFromSession>
  snapshot: MappingSnapshot
  plan: PcapPlanSnapshot
}

let processingClient: PcapProcessingWorkerClient | null = null

export function setProcessingClientsForTests(
  processing: PcapProcessingWorkerClient | null,
  mapping: MappingWorkerClient | null,
): void {
  processingClient?.terminate()
  processingClient = processing
  setSharedMappingClientForTests(mapping)
}

export function resetProcessingClients(): void {
  processingClient?.terminate()
  processingClient = null
}

function getProcessingClient(): PcapProcessingWorkerClient {
  if (!processingClient) processingClient = new PcapProcessingWorkerClient()
  return processingClient
}

function getMappingClient(): MappingWorkerClient {
  return getSharedMappingClient()
}

export function cancelActiveProcessing(generationId: string): void {
  processingClient?.cancel(generationId)
}

export function identitiesFromAnalysis(analysis: AnalysisResult): CanonicalIdentity[] {
  const seen = new Set<string>()
  const out: CanonicalIdentity[] = []
  for (const entity of analysis.entities) {
    const category = entity.category as EntityCategory
    const canonical = canonicalizePcapIdentity(category, entity.value)
    if (canonical === null) continue
    const constraint = defaultWireConstraint(category, canonical)
    if (constraint === null) continue
    const key = `${category}:${canonical}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ category, canonical, constraint })
  }
  return out
}

/**
 * PF-03: single pass over wire intents producing both the full per-occurrence intent list
 * (needed for mapping-closure validation and plan build — every occurrence's packet/offset
 * must survive) and the deduped identity list (needed to resolve required aliases). Doing
 * this as one pass instead of two (identitiesFromWireIntents + intentsFromWire, each
 * independently materializing a new object per intent) halves the main-thread work spent
 * turning wire intents into in-memory objects — on a large capture this array can be in the
 * millions, one entry per MAC/IP/port occurrence, not per unique identity.
 */
function intentsAndIdentitiesFromWire(
  wire: WireSourceDiscoveryPayload,
): { intents: TransformationIntent[]; identities: CanonicalIdentity[] } {
  const intents: TransformationIntent[] = []
  const identities: CanonicalIdentity[] = []
  const seenIdentityKeys = new Set<string>()
  for (const i of wire.intents) {
    const category = i.category as EntityCategory
    const constraint = i.constraint as CanonicalIdentity['constraint']
    intents.push({
      kind: 'entity-replacement',
      packetIndex: i.packetIndex,
      offset: i.offset,
      byteLength: i.byteLength,
      category,
      canonical: i.canonical,
      constraint,
      originalSpelling: i.originalSpelling,
    })
    // Matches dedupeIdentities()'s key exactly (mappingClosureValidation.ts) so this is a
    // behavior-preserving fusion of what was previously identitiesFromWireIntents()'s own
    // push-then-dedupeIdentities() pass.
    const identityKey = `${category}:${i.canonical}:${constraintKey(constraint)}:${i.originalSpelling ?? ''}`
    if (!seenIdentityKeys.has(identityKey)) {
      seenIdentityKeys.add(identityKey)
      identities.push({
        category,
        canonical: i.canonical,
        constraint,
        originalSpelling: i.originalSpelling,
        occurrence: { kind: 'packet', sourceId: 'wire', packetIndex: i.packetIndex },
      })
    }
  }
  return { intents, identities }
}

/** In-process orchestration for tests (no worker threads). */
export async function orchestrateInProcess(input: {
  blob: Blob
  fileName: string
  format: CaptureFormat
  policy: SanitizationPolicy
  profile: PcapProfile
  generationId: string
  sourceId: string
  mappingClient: MappingWorkerClient
}): Promise<ProcessingOrchestrationResult> {
  const session = await processCapture({
    blob: input.blob,
    fileName: input.fileName,
    format: input.format,
    policy: input.policy,
    generationId: input.generationId,
    sourceId: input.sourceId,
  })

  const identities = identitiesFromDiscovery(session.discovery)
  const { snapshot, unresolvedFailures } = await resolveSnapshotWithMappingClosure({
    generationId: input.generationId,
    sourceId: input.sourceId,
    identities,
    intents: session.discovery.intents,
    resolve: (ids) =>
      input.mappingClient.resolve(input.generationId, input.sourceId, ids, input.profile.mapping),
    packetNumberForIndex: (idx) => session.descriptors[idx]?.packetNumber,
  })
  const plan = buildPlanFromSession(session, snapshot, input.profile, undefined, {
    sourceId: input.sourceId,
    unresolvedClosureFailures: unresolvedFailures,
  })

  return {
    discovery: session.discovery,
    discoveryWire: discoveryToWire(session.discovery),
    containerWire: containerMetadataFromSession(session),
    snapshot,
    plan,
  }
}

/** Worker-based full load orchestration (Stage 9 production). */
export async function orchestrateViaWorkers(input: {
  blob: Blob
  fileName: string
  format: CaptureFormat
  policy: SanitizationPolicy
  profile: PcapProfile
  generationId: string
  sourceId: string
  onProgress?: (phase: string, done: number, total: number) => void
}): Promise<{
  discoveryWire: WireSourceDiscoveryPayload
  containerWire: WireContainerMetadata
  snapshot: MappingSnapshot
  planWire: import('../export/workerProtocol').WirePlanSnapshot
}> {
  const proc = getProcessingClient()
  const map = getMappingClient()

  const { discovery: discoveryWire, container: containerWire } = await proc.processCapture({
    generationId: input.generationId,
    sourceId: input.sourceId,
    format: input.format,
    policy: input.policy,
    blob: input.blob,
    onProgress: input.onProgress,
  })

  const { intents: intentsFromDiscovery, identities: fromIntents } = intentsAndIdentitiesFromWire(discoveryWire)
  const fromEntities: CanonicalIdentity[] = []
  for (const entity of discoveryWire.entities as Array<{ category: string; value: string }>) {
    const category = entity.category as EntityCategory
    const canonical = canonicalizePcapIdentity(category, entity.value)
    if (canonical === null) continue
    const constraint = defaultWireConstraint(category, canonical)
    if (constraint === null) continue
    fromEntities.push({ category, canonical, constraint })
  }

  const identities = dedupeIdentities([...fromIntents, ...fromEntities])
  const { snapshot, unresolvedFailures } = await resolveSnapshotWithMappingClosure({
    generationId: input.generationId,
    sourceId: input.sourceId,
    identities,
    intents: intentsFromDiscovery,
    resolve: (ids) => map.resolve(input.generationId, input.sourceId, ids, input.profile.mapping),
    packetNumberForIndex: (idx) => discoveryWire.summaries[idx]?.packetNumber,
  })
  // Soft-fail: thread wire-safe closure residuals into plan build (incidents, no values).
  const planWire = await proc.buildPlan({
    generationId: input.generationId,
    profile: input.profile,
    format: input.format,
    fileName: input.fileName,
    snapshot,
    unresolvedClosureFailures: unresolvedFailures.map((f) => ({
      packetIndex: f.packetIndex,
      category: f.category,
      reason: f.reason,
    })),
    onProgress: input.onProgress,
  })

  // R10 — drop per-identity intent seeds after resolve/plan; session coverage uses entityOccurrences.
  discoveryWire.intents = []

  return { discoveryWire, containerWire, snapshot, planWire }
}

/** Profile rebuild — re-resolve + build-plan using worker-retained session. */
export async function orchestratePlanRebuild(input: {
  blob: Blob
  fileName: string
  format: CaptureFormat
  policy: SanitizationPolicy
  profile: PcapProfile
  generationId: string
  sourceId: string
  mappingRevision: number
  analysis?: AnalysisResult
  /** Retained discovery intents when available — required for mapping closure. */
  intents?: readonly TransformationIntent[]
}): Promise<{
  snapshot: MappingSnapshot
  planWire: import('../export/workerProtocol').WirePlanSnapshot
}> {
  void input.blob
  void input.mappingRevision
  const proc = getProcessingClient()
  const map = getMappingClient()

  const identities = input.analysis ? identitiesFromAnalysis(input.analysis) : []
  const intents = input.intents ?? []
  const { snapshot, unresolvedFailures } = await resolveSnapshotWithMappingClosure({
    generationId: input.generationId,
    sourceId: input.sourceId,
    identities,
    intents,
    resolve: (ids) => map.resolve(input.generationId, input.sourceId, ids, input.profile.mapping),
  })
  const planWire = await proc.buildPlan({
    generationId: input.generationId,
    profile: input.profile,
    format: input.format,
    fileName: input.fileName,
    snapshot,
    unresolvedClosureFailures: unresolvedFailures.map((f) => ({
      packetIndex: f.packetIndex,
      category: f.category,
      reason: f.reason,
    })),
  })
  return { snapshot, planWire }
}
