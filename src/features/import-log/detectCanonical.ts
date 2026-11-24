/**
 * Send canonical LF text to the detection worker with regex-timeout auto-restart.
 * Stage 18: aliases come from MappingAuthority after detection completes.
 */

import type { RulesetConfig } from '../../domain/configSchema.ts'
import { createDefaultRulesetConfig, rulesetToDetectorConfig } from '../../domain/configSchema.ts'
import {
  DetectionWorkerClient,
  type DetectionProgressEvent,
  type DetectionResult,
} from '../../app/workerClient.ts'
import { patchEntitySummariesFromSnapshot } from '../../engine/entityRegistry.ts'
import { resolveTextIdentitiesBatch } from '../../mapping/textMappingPort.ts'
import { defaultTextWireConstraint } from '../../mapping/textCanonical.ts'
import { buildAliasLookup, mappingKey, type MappingSnapshot } from '../../mapping/types.ts'
import { canonicalizeTextIdentity } from '../../mapping/textCanonical.ts'
import { WORKER_ERROR } from '../../workers/protocol.ts'
import { iterateTextChunks, readFileByteChunks } from './chunking.ts'
import { getRecommendedChunkBytes } from './chunkSizing.ts'
import { ImportCancelledError } from './streamImport.ts'

interface DetectionInputChunk {
  readonly sequence: number
  readonly bytes?: ArrayBuffer
  readonly byteOffset?: number
  readonly byteLength?: number
  readonly text?: string
  readonly final: boolean
}

interface DetectionAttemptResult {
  readonly result: DetectionResult
  readonly profile: RulesetConfig
}

function isRegexTimeout(err: unknown): err is Error & { code: string; ruleId?: string } {
  return (
    err instanceof Error &&
    'code' in err &&
    (err as { code: string }).code === WORKER_ERROR.regexTimeout
  )
}

function replacementsRecordFromSnapshot(
  entities: DetectionResult['entities'],
  snapshot: MappingSnapshot,
): Record<string, string> {
  const lookup = buildAliasLookup(snapshot)
  const out: Record<string, string> = {}
  for (const e of entities) {
    const canonical = canonicalizeTextIdentity(e.category, e.originalSample) ?? e.normalized
    const alias = lookup.get(mappingKey(e.category, canonical))
    if (alias != null) out[e.key] = alias
  }
  return out
}

async function resolveSnapshotForEntities(
  generationId: string,
  sourceId: string,
  entities: DetectionResult['entities'],
  profile: RulesetConfig,
): Promise<MappingSnapshot> {
  const customRules = rulesetToDetectorConfig(profile).customRules
  const identities = entities.flatMap((e) => {
    const canonical = canonicalizeTextIdentity(e.category, e.originalSample)
    if (!canonical) return []
    return [{
      category: e.category,
      canonical,
      constraint: defaultTextWireConstraint(e.category, canonical, e.originalSample),
      originalSpelling: e.originalSample,
      source: { detectorId: e.sourceId },
    }]
  })
  return resolveTextIdentitiesBatch(generationId, sourceId, identities, customRules)
}

async function runDetectionAttempts(
  client: DetectionWorkerClient,
  initialProfile: RulesetConfig,
  createChunks: (attempt: number) => AsyncIterable<DetectionInputChunk> | Iterable<DetectionInputChunk>,
  options: {
    signal?: AbortSignal
    onProgress?: (ev: DetectionProgressEvent) => void
  },
): Promise<DetectionAttemptResult> {
  let profile = initialProfile
  const maxAttempts = profile.profile.rules.length + 1
  const unsubscribe = options.onProgress
    ? client.subscribeProgress(options.onProgress)
    : () => undefined
  let restartedRequestId: string | null = null

  client.clearFailedRuleIds()

  try {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const requestId = restartedRequestId ?? client.begin(profile)
      restartedRequestId = null
      const resultPromise = client.waitForResult(requestId)
      // The worker may reject while the producer is still yielding or while a callback throws.
      // Attach a handler immediately; the awaited promise below still preserves the rejection.
      void resultPromise.catch(() => undefined)

      try {
        for await (const chunk of createChunks(attempt)) {
          throwIfAborted(options.signal)
          await client.sendChunk(requestId, chunk)
        }
        return { result: await resultPromise, profile }
      } catch (err) {
        if (isRegexTimeout(err) && err.ruleId) {
          const restarted = client.isolateRuleAndRestart(err.ruleId, profile)
          profile = restarted.profile
          restartedRequestId = restarted.requestId
          options.onProgress?.({
            requestId: restarted.requestId,
            processedBytes: 0,
            processedLines: 0,
          })
          continue
        }
        throw err
      }
    }
  } finally {
    unsubscribe()
  }

  throw new Error('Analýza selhala — příliš mnoho neodpovídajících regex pravidel.')
}

/**
 * Detect directly from a replayable File/Blob byte stream.
 *
 * The first pass can synchronously mirror each chunk into the editor's LF decoder. If a custom
 * regex watchdog forces a retry, the Blob stream is reopened and only the worker pass is replayed.
 */
export async function detectFileBytes(
  client: DetectionWorkerClient,
  file: Blob,
  options: {
    profile?: RulesetConfig
    chunkBytes?: number
    signal?: AbortSignal
    onProgress?: (ev: DetectionProgressEvent) => void
    onFirstPassChunk?: (bytes: Uint8Array, final: boolean) => void
    sourceId?: string
    resolveMappings?: boolean
  } = {},
): Promise<DetectionResult> {
  const initialProfile = options.profile ?? createDefaultRulesetConfig()
  const chunkBytes = options.chunkBytes ?? getRecommendedChunkBytes()
  const detected = await runDetectionAttempts(
    client,
    initialProfile,
    async function* (attempt) {
      for await (const chunk of readFileByteChunks(file, chunkBytes)) {
        throwIfAborted(options.signal)
        if (attempt === 0 && options.onFirstPassChunk) {
          const view = new Uint8Array(chunk.bytes, chunk.byteOffset, chunk.byteLength)
          options.onFirstPassChunk(view, chunk.final)
        }
        yield chunk
      }
    },
    options,
  )

  if (options.resolveMappings === false) return detected.result

  const sourceId = options.sourceId ?? 'text-log'
  const snapshot = await resolveSnapshotForEntities(
    detected.result.requestId,
    sourceId,
    detected.result.entities,
    detected.profile,
  )
  const replacements = replacementsRecordFromSnapshot(detected.result.entities, snapshot)
  await client.syncEntityReplacements(detected.result.requestId, replacements)
  return {
    ...detected.result,
    entities: patchEntitySummariesFromSnapshot(detected.result.entities, snapshot),
  }
}

/** Stream a string to detection in bounded slices; useful for paste and in-memory reanalysis. */
export async function detectTextChunks(
  client: DetectionWorkerClient,
  text: string,
  options: {
    profile?: RulesetConfig
    chunkBytes?: number
    signal?: AbortSignal
    onProgress?: (ev: DetectionProgressEvent) => void
    onFirstPassChunk?: (text: string, final: boolean) => void
    sourceId?: string
    resolveMappings?: boolean
  } = {},
): Promise<DetectionResult> {
  const initialProfile = options.profile ?? createDefaultRulesetConfig()
  const chunkBytes = options.chunkBytes ?? getRecommendedChunkBytes()
  const detected = await runDetectionAttempts(
    client,
    initialProfile,
    function* (attempt) {
      for (const slice of iterateTextChunks(text, chunkBytes)) {
        if (attempt === 0) options.onFirstPassChunk?.(slice.text, slice.final)
        yield {
          sequence: slice.sequence,
          text: slice.text,
          final: slice.final,
        }
      }
    },
    options,
  )

  if (options.resolveMappings === false) return detected.result

  const sourceId = options.sourceId ?? 'text-log'
  const snapshot = await resolveSnapshotForEntities(
    detected.result.requestId,
    sourceId,
    detected.result.entities,
    detected.profile,
  )
  const replacements = replacementsRecordFromSnapshot(detected.result.entities, snapshot)
  await client.syncEntityReplacements(detected.result.requestId, replacements)
  return {
    ...detected.result,
    entities: patchEntitySummariesFromSnapshot(detected.result.entities, snapshot),
  }
}

export async function detectCanonicalText(
  client: DetectionWorkerClient,
  canonicalText: string,
  options: {
    profile?: RulesetConfig
    chunkBytes?: number
    signal?: AbortSignal
    onProgress?: (ev: DetectionProgressEvent) => void
    sourceId?: string
  } = {},
): Promise<DetectionResult> {
  return detectTextChunks(client, canonicalText, options)
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new ImportCancelledError()
}
