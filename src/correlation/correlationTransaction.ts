/**
 * Per-source staging transaction — discover → resolve staging → plan → atomic commit (Stage 24).
 */

import type { CustomRule } from '../domain/types'
import { getActiveProfile } from '../features/rules/activeProfile'
import { rulesetToDetectorConfig } from '../domain/configSchema'
import { getSharedMappingClient } from '../mapping/sharedMappingClient'
import type { MappingSnapshot } from '../mapping/types'
import { getActivePcapProfile } from '../pcap/profile/activePcapProfile'
import { requireSourceAdapter } from './adapterRegistry'
import {
  applySessionPolicyToCustomRules,
  correlationResolveOptionsFromSessionPolicy,
  isExportBlockedBySessionPolicy,
} from './profileCompatibility'
import { correlationResolveGate } from './sequentialGate'
import type {
  CorrelationError,
  CorrelationSourceDiscovery,
  CorrelationSourcePlan,
  CorrelationSourceRecord,
  SourceAdapter,
} from './types'

export interface SourceTransactionCommit {
  readonly discovery: CorrelationSourceDiscovery
  readonly plan: CorrelationSourcePlan
  readonly snapshot: MappingSnapshot
}

export interface SourceTransactionInput {
  readonly generationId: string
  readonly sourceId: string
  readonly record: CorrelationSourceRecord
  readonly adapter?: SourceAdapter
  readonly signal?: AbortSignal
  readonly onProgress?: (phase: string, done: number, total: number) => void
}

async function abortMappingStaging(): Promise<void> {
  try {
    await getSharedMappingClient().abortStaging()
  } catch {
    // worker may be unavailable during teardown
  }
}

export async function runSourceTransaction(
  input: SourceTransactionInput,
): Promise<SourceTransactionCommit | CorrelationError> {
  const adapter = input.adapter ?? requireSourceAdapter(input.record.kind)
  const client = getSharedMappingClient()

  let discovery: CorrelationSourceDiscovery
  try {
    discovery = await adapter.discover({
      generationId: input.generationId,
      sourceId: input.sourceId,
      file: input.record.file,
      signal: input.signal,
      onProgress: input.onProgress,
    })
  } catch (e) {
    await abortMappingStaging()
    const message = e instanceof Error ? e.message : String(e)
    if (input.signal?.aborted) {
      return { code: 'correlation-staging-aborted', message: 'Source staging cancelled', sourceId: input.sourceId }
    }
    return { code: 'correlation-discover-failed', message, sourceId: input.sourceId }
  }

  if (input.signal?.aborted) {
    await abortMappingStaging()
    return { code: 'correlation-staging-aborted', message: 'Source staging cancelled', sourceId: input.sourceId }
  }

  const customRules: readonly CustomRule[] =
    discovery.kind === 'text'
      ? applySessionPolicyToCustomRules(rulesetToDetectorConfig(getActiveProfile()).customRules)
      : []

  if (isExportBlockedBySessionPolicy()) {
    await abortMappingStaging()
    return {
      code: 'correlation-profile-conflict',
      message: 'Export blocked until profile compatibility is resolved or rebuild completes',
      sourceId: input.sourceId,
    }
  }

  const correlationOptions = correlationResolveOptionsFromSessionPolicy()

  let previewSnapshot: MappingSnapshot
  try {
    input.onProgress?.('resolve', 0, 1)
    previewSnapshot = await correlationResolveGate.run(`resolve-staging:${input.sourceId}`, () =>
      client.resolveStaging(
        input.generationId,
        input.sourceId,
        [...discovery.identities],
        getActivePcapProfile().mapping,
        customRules,
        correlationOptions,
      ),
    )
    input.onProgress?.('resolve', 1, 1)
  } catch (e) {
    await abortMappingStaging()
    const message = e instanceof Error ? e.message : String(e)
    return { code: 'correlation-resolve-failed', message, sourceId: input.sourceId }
  }

  if (input.signal?.aborted) {
    await abortMappingStaging()
    return { code: 'correlation-staging-aborted', message: 'Source staging cancelled', sourceId: input.sourceId }
  }

  let plan: CorrelationSourcePlan
  try {
    input.onProgress?.('plan', 0, 1)
    plan = await adapter.buildPlan({
      generationId: input.generationId,
      sourceId: input.sourceId,
      snapshot: previewSnapshot,
      discovery,
    })
    input.onProgress?.('plan', 1, 1)
  } catch (e) {
    await abortMappingStaging()
    const message = e instanceof Error ? e.message : String(e)
    return { code: 'correlation-plan-failed', message, sourceId: input.sourceId }
  }

  let snapshot: MappingSnapshot
  try {
    snapshot = await client.commitStaging()
  } catch (e) {
    await abortMappingStaging()
    const message = e instanceof Error ? e.message : String(e)
    return { code: 'correlation-resolve-failed', message, sourceId: input.sourceId }
  }

  return {
    discovery,
    plan: { ...plan, outputFileName: input.record.outputFileName } as CorrelationSourcePlan,
    snapshot,
  }
}

export async function abortActiveSourceTransaction(): Promise<void> {
  await abortMappingStaging()
}
