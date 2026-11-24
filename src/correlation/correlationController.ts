/**
 * Application commands for correlation session staging and processing (Stage 23 / 24).
 */

import { resetSharedMappingClient, getSharedMappingClient } from '../mapping/sharedMappingClient'
import { releaseMappingSession } from '../mapping/sessionLifecycle'
import { SourceKind } from '../domain/sourceArtifact'
import { getActiveProfile } from '../features/rules/activeProfile'
import { getActivePcapProfile } from '../pcap/profile/activePcapProfile'
import { useAppStore } from '../app/store'
import {
  clearSourceAdapterRegistry,
  getSourceAdapter,
  registerSourceAdapter,
} from './adapterRegistry'
import {
  buildStagedSourceRecord,
  processCorrelationSession,
  processSingleSourceInSession,
} from './correlationSession'
import {
  appendStagedDescriptor,
  clearCorrelationSessionModel,
  createCorrelationSessionModel,
  getCorrelationSessionModel,
  removeSourceRecord,
  setCorrelationAbort,
  setCorrelationMappingRevision,
} from './correlationSessionModel'
import {
  clearCorrelationManifest,
  getPublishedCorrelationManifest,
  isCorrelationManifestStale,
  publishCorrelationManifest,
} from './correlationManifest'
import { getCorrelationSessionView, resetCorrelationViewModel } from './correlationViewModel'
import { correlationResolveGate } from './sequentialGate'
import { abortActiveSourceTransaction } from './correlationTransaction'
import { releaseTextMaterialization, selectTextSourceForPreview } from './textMaterialization'
import { resetCorrelationExportModel } from './export/correlationExportModel'
import { textSourceAdapter } from './textSourceAdapter'
import { pcapSourceAdapter } from './pcapSourceAdapter'
import { SOURCE_PROBE_HEAD_BYTES } from '../domain/capabilityContract'
import {
  correlationSourceLimits,
  sumDescriptorBytes,
  sumExistingSourceBytes,
  sumPasteDescriptorBytes,
  validateAggregateBytes,
  validateDescriptorCount,
  validatePasteAggregateBytes,
  validateUniqueSourceIds,
} from './sourceLimits'
import { resetCorrelationProgress } from './correlationProgressModel'
import { resetCorrelationReviewModel } from './correlationReviewModel'
import {
  compileAndEvaluateSessionPolicy,
  getProfileCompatibilityReport,
  resetCorrelationSessionPolicy,
  resetGlobalRebuildStateForTests,
  resolveProfileConflict,
  sessionPolicyAllowsProcessing,
  type ProfileCompatibilityReport,
} from './profileCompatibility'
import type { CrossFormatCategory } from '../mapping/crossFormat/types'
import type { ProfileConflictResolution } from './profileCompatibility/types'
import type {
  AddCorrelationSourceResult,
  CorrelationError,
  ProcessCorrelationResult,
  RemoveCorrelationSourceResult,
  StageCorrelationResult,
  StagedSourceDescriptor,
} from './types'

let adaptersBootstrapped = false

export function bootstrapDefaultSourceAdapters(): void {
  if (!getSourceAdapter('text')) {
    registerSourceAdapter(textSourceAdapter)
  }
  if (!getSourceAdapter('pcap')) {
    registerSourceAdapter(pcapSourceAdapter)
  }
  adaptersBootstrapped = true
  void adaptersBootstrapped
}

export function resetCorrelationAdaptersForTests(): void {
  clearSourceAdapterRegistry()
  adaptersBootstrapped = false
}

function compilePolicyForCurrentSession(): ProfileCompatibilityReport | null {
  const model = getCorrelationSessionModel()
  if (!model) return null
  const kinds = [...new Set([...model.sources.values()].map((s) => s.kind))]
  // Text ruleset and PCAP policy are independent — never read PCAP from the text profile.
  return compileAndEvaluateSessionPolicy({
    sourceKinds: kinds,
    textProfile: kinds.includes(SourceKind.Text) ? getActiveProfile() : undefined,
    pcapProfile: kinds.includes(SourceKind.Pcap) ? getActivePcapProfile() : undefined,
  })
}

function bumpCorrelationView(): void {
  useAppStore.getState().bumpCorrelationEpoch()
  const view = getCorrelationSessionView()
  useAppStore.getState().setCorrelationView({
    phase: view.phase,
    sourceCount: view.sourceCount,
    mappingRevision: view.mappingRevision,
  })
}

function newSessionId(): string {
  return `corr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}

function newGenerationId(): string {
  return `gen-${Date.now().toString(36)}`
}

async function readHeadBytes(file: File, n = SOURCE_PROBE_HEAD_BYTES): Promise<Uint8Array> {
  const buf = await file.slice(0, n).arrayBuffer()
  return new Uint8Array(buf)
}

async function validateDescriptor(
  d: StagedSourceDescriptor,
  limits: ReturnType<typeof correlationSourceLimits>,
  existingIds: ReadonlySet<string>,
): Promise<CorrelationError | null> {
  if (existingIds.has(d.sourceId)) {
    return {
      code: 'correlation-duplicate-source-id',
      message: `Duplicate source id: ${d.sourceId}`,
      sourceId: d.sourceId,
    }
  }

  const adapter = getSourceAdapter(d.kind)
  if (!adapter) {
    return {
      code: 'correlation-adapter-missing',
      message: `No adapter for kind ${d.kind}`,
      sourceId: d.sourceId,
    }
  }

  const head = await readHeadBytes(d.file)
  const probe = adapter.probe(head, d.file)
  if (!probe.ok) {
    return { code: 'correlation-probe-failed', message: probe.message, sourceId: d.sourceId }
  }

  const preflight = await adapter.preflight(d.file, limits)
  if (!preflight.ok) {
    return { code: 'correlation-preflight-failed', message: preflight.message, sourceId: d.sourceId }
  }

  return null
}

function validateSessionCapacity(
  descriptors: readonly StagedSourceDescriptor[],
  existingCount: number,
  existingBytes: number,
  existingPasteBytes = 0,
): CorrelationError | null {
  const totalCount = existingCount + descriptors.length
  const countErr = validateDescriptorCount(totalCount)
  if (countErr) return countErr

  const totalBytes = existingBytes + sumDescriptorBytes(descriptors)
  const aggErr = validateAggregateBytes(totalBytes)
  if (aggErr) return aggErr

  const pasteBytes = existingPasteBytes + sumPasteDescriptorBytes(descriptors)
  const pasteErr = validatePasteAggregateBytes(pasteBytes)
  if (pasteErr) return pasteErr

  return null
}

function sumExistingPasteBytes(sources: Iterable<{ byteLength: number; inputKind: 'file' | 'paste' }>): number {
  let total = 0
  for (const s of sources) {
    if (s.inputKind === 'paste') total += s.byteLength
  }
  return total
}

/**
 * Stage one or more typed source descriptors — probe + preflight only (Stage 23).
 */
export async function stageCorrelationDescriptors(
  descriptors: readonly StagedSourceDescriptor[],
): Promise<StageCorrelationResult | CorrelationError> {
  bootstrapDefaultSourceAdapters()

  const countErr = validateDescriptorCount(descriptors.length)
  if (countErr) return countErr

  const dupErr = validateUniqueSourceIds(descriptors)
  if (dupErr) return dupErr

  const capErr = validateSessionCapacity(descriptors, 0, 0)
  if (capErr) return capErr

  const limits = correlationSourceLimits()
  const existingIds = new Set<string>()

  for (const d of descriptors) {
    const err = await validateDescriptor(d, limits, existingIds)
    if (err) return err
    existingIds.add(d.sourceId)
  }

  clearCorrelationSessionModel()
  clearCorrelationManifest()
  releaseTextMaterialization()

  const sessionId = newSessionId()
  const generationId = newGenerationId()

  createCorrelationSessionModel({
    sessionId,
    generationId,
    descriptors,
    buildRecord: buildStagedSourceRecord,
  })

  compilePolicyForCurrentSession()

  bumpCorrelationView()
  return { ok: true, sessionId, sourceCount: descriptors.length, totalBytes: sumDescriptorBytes(descriptors) }
}

export async function runCorrelationSession(): Promise<ProcessCorrelationResult | CorrelationError> {
  bootstrapDefaultSourceAdapters()
  if (!sessionPolicyAllowsProcessing()) {
    return {
      code: 'correlation-profile-conflict',
      message: 'Unresolved profile compatibility conflicts block correlation processing',
    }
  }
  const result = await processCorrelationSession()
  bumpCorrelationView()
  return result
}

/**
 * Add a compatible source to a ready session via staging transaction (Stage 24).
 */
export async function addCorrelationSource(
  descriptor: StagedSourceDescriptor,
  options?: { signal?: AbortSignal },
): Promise<AddCorrelationSourceResult | CorrelationError> {
  bootstrapDefaultSourceAdapters()
  const model = getCorrelationSessionModel()
  if (!model || model.phase !== 'ready') {
    return { code: 'correlation-not-ready', message: 'Session must be ready before adding sources' }
  }

  const existingIds = new Set(model.sources.keys())
  const existingBytes = sumExistingSourceBytes(model.sources.values())

  const capErr = validateSessionCapacity([descriptor], model.sources.size, existingBytes, sumExistingPasteBytes(model.sources.values()))
  if (capErr) return capErr

  const limits = correlationSourceLimits()
  const valErr = await validateDescriptor(descriptor, limits, existingIds)
  if (valErr) return valErr

  const revisionBefore = model.mappingRevision ?? getSharedMappingClient().getPublishedRevision()
  const existingPlans = snapshotExistingPlans(model)

  appendStagedDescriptor(descriptor, buildStagedSourceRecord)
  compilePolicyForCurrentSession()
  if (!sessionPolicyAllowsProcessing()) {
    removeSourceRecord(descriptor.sourceId)
    bumpCorrelationView()
    return {
      code: 'correlation-profile-conflict',
      message: 'Profile compatibility conflict blocks adding this source',
      sourceId: descriptor.sourceId,
    }
  }

  const processed = await processSingleSourceInSession(descriptor.sourceId, options?.signal)
  if (!('ok' in processed) || !processed.ok) {
    removeSourceRecord(descriptor.sourceId)
    bumpCorrelationView()
    return processed as CorrelationError
  }

  for (const [sourceId, planJson] of existingPlans) {
    const record = model.sources.get(sourceId)
    if (!record?.plan) continue
    if (JSON.stringify(record.plan) !== planJson) {
      throw new Error(`Existing plan mutated for ${sourceId} during add`)
    }
  }

  if ((model.mappingRevision ?? 0) < revisionBefore) {
    return { code: 'correlation-stale-generation', message: 'Mapping revision regressed after add' }
  }

  bumpCorrelationView()
  return {
    ok: true,
    sourceId: descriptor.sourceId,
    mappingRevision: processed.mappingRevision,
    sourceCount: model.sources.size,
  }
}

/**
 * Remove a source — releases occurrences and scrubs unused plaintext; aliases are retained (Stage 24).
 */
export async function removeCorrelationSource(
  sourceId: string,
): Promise<RemoveCorrelationSourceResult | CorrelationError> {
  const model = getCorrelationSessionModel()
  if (!model || model.phase !== 'ready') {
    return { code: 'correlation-not-ready', message: 'Session must be ready before removing sources' }
  }

  const record = model.sources.get(sourceId)
  if (!record) {
    return { code: 'correlation-source-missing', message: `Unknown source: ${sourceId}`, sourceId }
  }

  const remainingPlans = snapshotExistingPlans(model, sourceId)
  const client = getSharedMappingClient()

  await correlationResolveGate.run(`release:${sourceId}`, async () => {
    for (const id of record.discovery?.identities ?? []) {
      if (id.occurrence && id.occurrence.sourceId === sourceId) {
        await client.releaseOccurrence(id.category, id.canonical, id.occurrence)
      }
    }
  })

  selectTextSourceForPreview(null)
  releaseTextMaterialization()
  removeSourceRecord(sourceId)

  const publishedRevision = getSharedMappingClient().getPublishedRevision()
  setCorrelationMappingRevision(publishedRevision)

  publishCorrelationManifest({
    sessionId: model.sessionId,
    generationId: model.generationId,
    mappingRevision: publishedRevision,
    sourceIds: [...model.sources.keys()],
  })

  for (const [sid, planJson] of remainingPlans) {
    const remaining = model.sources.get(sid)
    if (!remaining?.plan) continue
    if (JSON.stringify(remaining.plan) !== planJson) {
      throw new Error(`Remaining plan mutated for ${sid} during remove`)
    }
  }

  bumpCorrelationView()
  return {
    ok: true,
    sourceId,
    mappingRevision: getSharedMappingClient().getPublishedRevision(),
    sourceCount: model.sources.size,
    aliasRetained: true,
  }
}

function snapshotExistingPlans(
  model: NonNullable<ReturnType<typeof getCorrelationSessionModel>>,
  excludeSourceId?: string,
): Map<string, string> {
  const out = new Map<string, string>()
  for (const [id, record] of model.sources) {
    if (excludeSourceId && id === excludeSourceId) continue
    if (record.plan) out.set(id, JSON.stringify(record.plan))
  }
  return out
}

export function cancelCorrelationSession(): void {
  getCorrelationSessionModel()?.abort?.abort()
  setCorrelationAbort(null)
  correlationResolveGate.reset()
  void abortActiveSourceTransaction()
  bumpCorrelationView()
}

export function clearCorrelationSession(): void {
  cancelCorrelationSession()
  clearCorrelationSessionModel()
  resetCorrelationViewModel()
  resetCorrelationReviewModel()
  resetCorrelationProgress()
  resetCorrelationExportModel()
  clearCorrelationManifest()
  releaseTextMaterialization()
  releaseMappingSession()
  resetSharedMappingClient()
  resetCorrelationSessionPolicy()
  resetGlobalRebuildStateForTests()
  bumpCorrelationView()
}

export function getCorrelationProfileCompatibilityReport(): ProfileCompatibilityReport | null {
  return getProfileCompatibilityReport()
}

export function resolveProfileCompatibilityConflict(
  category: CrossFormatCategory,
  resolution: ProfileConflictResolution,
): ProfileCompatibilityReport | null {
  const report = resolveProfileConflict(category, resolution)
  bumpCorrelationView()
  return report
}

export function getCorrelationView() {
  return getCorrelationSessionView()
}

export function isSingleSourceSession(): boolean {
  const view = getCorrelationSessionView()
  return view.sourceCount === 1
}

export function isPublishedManifestStale(): boolean {
  const manifest = getPublishedCorrelationManifest()
  if (!manifest) return false
  return isCorrelationManifestStale(manifest)
}

export function selectCorrelationTextPreview(sourceId: string | null): void {
  selectTextSourceForPreview(sourceId)
  bumpCorrelationView()
}
